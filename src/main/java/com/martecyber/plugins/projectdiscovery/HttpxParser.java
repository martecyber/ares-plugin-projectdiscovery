package com.martecyber.plugins.projectdiscovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Parses httpx JSONL output (httpx -json).
 *
 * Key fields used: url, input, host (resolved IP), port, scheme, status_code, title, tech, webserver.
 *
 * Asset chain: DOMAIN (no domain_a link — httpx doesn't know the DNS record type/chain
 *              behind its resolved IP) → IP → INTERFACE → SERVICE
 *                                                             ↑
 *                              WEB_APPLICATION (webapp_service, webapp_domain)
 */
public class HttpxParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()    { return "httpx"; }
    @Override public String getDisplayName() { return "httpx"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json", ".jsonl"}; }

    @Override
    public boolean validate(byte[] content) {
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        return first.startsWith("{") && first.contains("\"url\"") && first.contains("\"status_code\"");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        Set<String> seen   = new HashSet<>();
        ScannerParserUtils.forEachJsonLine(content, line -> {
            try {
                processEntry(MAPPER.readTree(line), result, seen);
            } catch (Exception e) {
                result.addWarning("Skipping entry: " + e.getMessage());
            }
        });
        return result;
    }

    private void processEntry(JsonNode node, ParseResult result, Set<String> seen) {
        String url    = node.path("url").asText(null);
        String input  = node.path("input").asText(null);   // original target (domain or IP)
        // httpx puts the resolved IP in "host" when probing by domain
        String ip     = firstNonBlank(node.path("ip").asText(null), node.path("host").asText(null));
        String portS  = node.path("port").asText(null);
        String scheme = node.path("scheme").asText(null);
        String title  = node.path("title").asText(null);
        String wsvr   = node.path("webserver").asText(null);
        int    sc     = node.path("status_code").asInt(0);

        if (url == null || url.isBlank()) return;

        String webId = ScannerParserUtils.baseUrl(url);

        // IP chain
        boolean hasIp = ip != null && !ip.isBlank() && ScannerParserUtils.isIp(ip);
        if (hasIp) ScannerParserUtils.emitHostChain(ip, result, seen);

        // Domain (input field when it's not a bare IP)
        String domain = null;
        if (input != null && !input.isBlank() && !ScannerParserUtils.isIp(input)) {
            domain = stripScheme(input);
            if (seen.add(domain)) result.addAsset(new ParsedAsset(domain, AssetType.DOMAIN, Map.of()));
        }

        // Service
        String svcId = null;
        if (hasIp && portS != null && !portS.isBlank()) {
            try {
                int port = Integer.parseInt(portS.trim());
                svcId = ScannerParserUtils.emitService(ip, port, "tcp", scheme, result, seen);
            } catch (NumberFormatException ignored) {}
        }

        // Web application
        Map<String, Object> meta = new LinkedHashMap<>();
        if (title != null && !title.isBlank()) meta.put("title", title);
        if (wsvr  != null && !wsvr.isBlank())  meta.put("server", wsvr);
        if (sc > 0) meta.put("statusCode", sc);

        if (seen.add(webId)) result.addAsset(new ParsedAsset(webId, AssetType.WEB_APPLICATION, meta));
        if (svcId  != null)  result.addLink(webId, svcId,  AssetLinkType.WEBAPP_SERVICE);
        if (domain != null)  result.addLink(webId, domain, AssetLinkType.WEBAPP_DOMAIN);

        // Technologies
        JsonNode tech = node.get("tech");
        if (tech != null && tech.isArray()) {
            tech.forEach(t -> {
                String name = t.asText("").trim();
                if (!name.isBlank()) {
                    if (seen.add("tech:" + name))
                        result.addAsset(new ParsedAsset(name, AssetType.TECHNOLOGY, Map.of()));
                    result.addLink(webId, name, AssetLinkType.WEBAPP_TECHNOLOGY);
                }
            });
        }
    }

    private static String stripScheme(String s) {
        if (s == null) return null;
        s = s.trim();
        if (s.startsWith("https://")) s = s.substring(8);
        else if (s.startsWith("http://")) s = s.substring(7);
        int slash = s.indexOf('/');
        return slash >= 0 ? s.substring(0, slash) : s;
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
