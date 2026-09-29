package com.martecyber.plugins.projectdiscovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Parses subfinder output — plain text (one domain per line) or JSONL.
 *
 * Plain:  sub.example.com
 * JSON:   {"host":"sub.example.com","input":"example.com","source":"certspotter","type":"subdomain"}
 */
public class SubfinderParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()    { return "subfinder"; }
    @Override public String getDisplayName() { return "Subfinder"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".txt", ".json", ".jsonl"}; }

    @Override
    public boolean validate(byte[] content) {
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        if (first.startsWith("{")) {
            // JSONL: subfinder has "host" + ("source" or "input")
            return first.contains("\"host\"") &&
                   (first.contains("\"source\"") || first.contains("\"input\"") || first.contains("\"type\""));
        }
        // Plain text: looks like a hostname (no spaces, contains dot)
        return first.matches("[a-zA-Z0-9._*-]+\\.[a-zA-Z]{2,}");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        String first = ScannerParserUtils.firstNonEmptyLine(content);

        if (first.startsWith("{")) {
            parseJsonl(content, result);
        } else {
            parsePlain(content, result);
        }
        return result;
    }

    private void parsePlain(byte[] content, ParseResult result) {
        Set<String> seen = new HashSet<>();
        new String(content, StandardCharsets.UTF_8).lines()
            .map(String::trim)
            .filter(l -> !l.isBlank() && l.contains(".") && !l.contains(" "))
            .forEach(host -> {
                if (seen.add(host)) result.addAsset(new ParsedAsset(host, AssetType.DOMAIN, Map.of()));
            });
    }

    private void parseJsonl(byte[] content, ParseResult result) {
        Set<String> seen = new HashSet<>();
        ScannerParserUtils.forEachJsonLine(content, line -> {
            try {
                JsonNode node = MAPPER.readTree(line);
                String host = node.path("host").asText(null);
                if (host != null && !host.isBlank() && seen.add(host)) {
                    result.addAsset(new ParsedAsset(host, AssetType.DOMAIN, Map.of()));
                }
            } catch (Exception e) {
                result.addWarning("Skipping line: " + e.getMessage());
            }
        });
    }
}
