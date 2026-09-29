package com.martecyber.plugins.projectdiscovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import com.martecyber.ares.imports.ParseContext;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses Katana web-crawler JSONL output (katana -jsonl / -json).
 *
 * Supports both the nested format (katana ≥ v1.x):
 *   {"timestamp":"…","request":{"endpoint":"https://host/path","source":"…","method":"GET",…},"response":{"status_code":200,"technologies":[…]}}
 * and the flat format (older builds):
 *   {"endpoint":"https://host/path","source":"https://host/"}
 *
 * Asset chain built per crawled URL:
 *   DOMAIN (host)
 *   └─ webapp_domain ─▶ WEB_APPLICATION (scheme://host[:port])
 *                          └─ webapp_endpoint ─▶ WEB_ENDPOINT (full URL)
 *
 * Technologies from "response.technologies" are emitted as TECHNOLOGY assets
 * linked to the WEB_APPLICATION (webapp_technology).
 */
public class KatanaParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()    { return "katana"; }
    @Override public String getDisplayName() { return "Katana"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".jsonl", ".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        // Either nested (has "request") or flat (has "endpoint" + "source")
        return first.startsWith("{")
            && (first.contains("\"request\"") || (first.contains("\"endpoint\"") && first.contains("\"source\"")));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        return parse(content, ParseContext.NONE);
    }

    @Override
    public ParseResult parse(byte[] content, ParseContext ctx) throws Exception {
        ParseResult result = new ParseResult();
        Set<String> seen  = new HashSet<>();
        boolean filterDisabled = ctx.filterDisabled();
        Set<String> allowedDomains = ctx.allowedDomains();
        ScannerParserUtils.forEachJsonLine(content, line -> {
            try {
                processEntry(MAPPER.readTree(line), result, seen, filterDisabled, allowedDomains);
            } catch (Exception e) {
                result.addWarning("Skipping entry: " + e.getMessage());
            }
        });
        return result;
    }

    private void processEntry(JsonNode node, ParseResult result, Set<String> seen,
                               boolean filterDisabled, Set<String> allowedDomains) {
        // Resolve endpoint and status_code from both nested and flat formats
        String endpoint;
        String source;
        int    statusCode = 0;
        JsonNode technologies = null;

        if (node.has("request")) {
            // Nested format
            JsonNode req = node.path("request");
            JsonNode res = node.path("response");
            endpoint      = req.path("endpoint").asText(null);
            source        = req.path("source").asText(null);
            statusCode    = res.path("status_code").asInt(0);
            technologies  = res.has("technologies") ? res.get("technologies") : null;
        } else {
            // Flat format
            endpoint   = node.path("endpoint").asText(null);
            source     = node.path("source").asText(null);
            statusCode = node.path("status_code").asInt(0);
            technologies = node.has("technologies") ? node.get("technologies") : null;
        }

        if (endpoint == null || endpoint.isBlank()) return;

        String webAppId   = ScannerParserUtils.baseUrl(endpoint);
        String domainHost = extractHost(endpoint);
        if (webAppId == null || domainHost == null) return;

        // Drop external endpoints unless the filter is disabled or the endpoint host
        // matches an explicitly in-scope entry. Katana reports discovered links even when
        // -fs rdn prevents crawling them; without this gate they pollute the inventory.
        if (!filterDisabled) {
            String sourceHost = extractHost(source);
            boolean allowedBySource = isSameDomainFamily(domainHost, sourceHost);
            boolean allowedByScope  = !allowedDomains.isEmpty() &&
                allowedDomains.stream().anyMatch(d -> isSameDomainFamily(domainHost, d));
            if (!allowedBySource && !allowedByScope) return;
        }

        // DOMAIN asset
        if (!ScannerParserUtils.isIp(domainHost)) {
            if (seen.add(domainHost))
                result.addAsset(new ParsedAsset(domainHost, AssetType.DOMAIN, Map.of()));
        }

        // WEB_APPLICATION asset (scheme://host[:port])
        if (seen.add(webAppId)) {
            result.addAsset(new ParsedAsset(webAppId, AssetType.WEB_APPLICATION, Map.of()));
            if (!ScannerParserUtils.isIp(domainHost))
                result.addLink(webAppId, domainHost, AssetLinkType.WEBAPP_DOMAIN);
        }

        // WEB_ENDPOINT asset — identifier is the URL without query string.
        // Query params are accumulated in metadata["params"] as {name: [value, ...]} across
        // all observed URLs that share the same path.
        String endpointId = normaliseEndpointPath(endpoint);
        if (endpointId != null) {
            Map<String, String> rawParams = extractQueryParams(endpoint);
            boolean hasSource = source != null && !source.isBlank() && !source.equals(endpoint);
            final int finalStatusCode = statusCode;
            final String finalSource = source;
            if (seen.add(endpointId)) {
                Map<String, Object> meta = new LinkedHashMap<>();
                if (statusCode > 0) meta.put("statusCodes", new ArrayList<>(List.of(statusCode)));
                if (hasSource) meta.put("sources", new ArrayList<>(List.of(source)));
                if (!rawParams.isEmpty()) {
                    Map<String, List<String>> params = new LinkedHashMap<>();
                    rawParams.forEach((k, v) -> { List<String> l = new ArrayList<>(); l.add(v); params.put(k, l); });
                    meta.put("params", params);
                }
                result.addAsset(new ParsedAsset(endpointId, AssetType.WEB_ENDPOINT, meta));
                result.addLink(webAppId, endpointId, AssetLinkType.WEBAPP_ENDPOINT);
            } else {
                // Endpoint already registered this import — merge new observations into the existing mutable meta map
                result.getAssets().stream()
                    .filter(a -> AssetType.WEB_ENDPOINT.equals(a.getType()) && endpointId.equals(a.getIdentifier()))
                    .findFirst().ifPresent(existing -> {
                        if (!rawParams.isEmpty()) mergeParams(existing.getMetadata(), rawParams);
                        if (finalStatusCode > 0) mergeArrayValue(existing.getMetadata(), "statusCodes", finalStatusCode);
                        if (hasSource) mergeArrayValue(existing.getMetadata(), "sources", finalSource);
                    });
            }
        }

        // Technologies
        if (technologies != null && technologies.isArray()) {
            final String appId = webAppId;
            technologies.forEach(t -> {
                String name = t.isTextual() ? t.asText("").trim() : t.path("name").asText("").trim();
                if (!name.isBlank()) {
                    if (seen.add("tech:" + name))
                        result.addAsset(new ParsedAsset(name, AssetType.TECHNOLOGY, Map.of()));
                    result.addLink(appId, name, AssetLinkType.WEBAPP_TECHNOLOGY);
                }
            });
        }
    }

    /**
     * Returns true when {@code host} belongs to the same domain family as {@code sourceHost},
     * using the same semantics as Katana's {@code -fs rdn} (root-domain scope):
     * <ol>
     *   <li>Exact hostname match</li>
     *   <li>One is a subdomain of the other (e.g. api.example.com ↔ www.example.com)</li>
     *   <li>They share the same registered domain (last two labels, e.g. example.com)</li>
     * </ol>
     * IP addresses are always kept — they are direct crawl targets, never external noise.
     * A null/blank sourceHost means no source context; returns true (permissive).
     */
    private static boolean isSameDomainFamily(String host, String sourceHost) {
        if (host == null || sourceHost == null || sourceHost.isBlank()) return true;
        if (ScannerParserUtils.isIp(host)) return true;
        String h = host.toLowerCase();
        String s = sourceHost.toLowerCase();
        if (h.equals(s)) return true;
        if (h.endsWith("." + s) || s.endsWith("." + h)) return true;
        return registeredDomain(h).equals(registeredDomain(s));
    }

    /** Returns the last two hostname labels (e.g. "sub.example.com" → "example.com"). */
    private static String registeredDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length <= 2) return host;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    /** Extracts bare hostname (no port, no scheme) from a URL. */
    private static String extractHost(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI uri = URI.create(url.trim());
            return uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns the endpoint identifier — scheme://host[:port]/path without query string or fragment.
     * Trailing "/" on root paths is stripped so "https://host/" collapses to "https://host".
     */
    private static String normaliseEndpointPath(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI uri = URI.create(url.trim());
            String path = uri.getRawPath() != null ? uri.getRawPath() : "";
            String base = ScannerParserUtils.baseUrl(url);
            if (base == null) return null;
            if (path.isEmpty() || path.equals("/")) return base;
            return base + path;
        } catch (Exception e) {
            return null;
        }
    }

    /** Parses query string into a flat name→value map (last value wins for duplicates). */
    private static Map<String, String> extractQueryParams(String url) {
        Map<String, String> result = new LinkedHashMap<>();
        try {
            String query = URI.create(url.trim()).getRawQuery();
            if (query == null || query.isBlank()) return result;
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String name  = eq >= 0 ? pair.substring(0, eq)  : pair;
                String value = eq >= 0 ? pair.substring(eq + 1) : "";
                result.put(java.net.URLDecoder.decode(name,  java.nio.charset.StandardCharsets.UTF_8),
                           java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {}
        return result;
    }

    /** Merges rawParams into existing metadata["params"] map. */
    @SuppressWarnings("unchecked")
    private static void mergeParams(Map<String, Object> meta, Map<String, String> rawParams) {
        Map<String, List<String>> params = (Map<String, List<String>>) meta.computeIfAbsent(
            "params", k -> new LinkedHashMap<String, List<String>>());
        rawParams.forEach((k, v) -> {
            List<String> list = params.computeIfAbsent(k, x -> new ArrayList<>());
            if (!list.contains(v)) list.add(v);
        });
    }

    /** Appends value to metadata[key] (a list of distinct observed values) if not already present. */
    @SuppressWarnings("unchecked")
    private static void mergeArrayValue(Map<String, Object> meta, String key, Object value) {
        List<Object> list = (List<Object>) meta.computeIfAbsent(key, k -> new ArrayList<Object>());
        String vs = String.valueOf(value);
        if (list.stream().noneMatch(v -> String.valueOf(v).equals(vs))) list.add(value);
    }
}
