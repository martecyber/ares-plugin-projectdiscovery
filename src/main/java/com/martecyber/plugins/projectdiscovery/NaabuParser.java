package com.martecyber.plugins.projectdiscovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Parses naabu JSONL output (naabu -json).
 *
 * {"ip":"1.2.3.4","port":80,"protocol":"tcp","host":"sub.example.com","timestamp":"..."}
 *
 * Asset chain: IP → INTERFACE → SERVICE
 *              DOMAIN (if host is a hostname, not bare IP) — asset only, no domain_a link:
 *              naabu doesn't know the DNS record type/chain behind that hostname.
 */
public class NaabuParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()      { return "naabu"; }
    @Override public String getDisplayName() { return "Naabu"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json", ".jsonl"}; }

    @Override
    public boolean validate(byte[] content) {
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        // naabu: flat "port" (number) + "protocol" + "ip" — not "ports" array like masscan
        return first.startsWith("{")
            && first.contains("\"ip\"")
            && first.contains("\"port\"")
            && first.contains("\"protocol\"")
            && !first.contains("\"ports\"");    // distinguish from masscan
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
        String ip    = node.path("ip").asText(null);
        int    port  = node.path("port").asInt(0);
        String proto = node.path("protocol").asText("tcp");
        String host  = node.path("host").asText(null); // original target (may be domain)

        if (ip == null || ip.isBlank() || !ScannerParserUtils.isIp(ip) || port <= 0) return;

        ScannerParserUtils.emitHostChain(ip, result, seen);
        ScannerParserUtils.emitService(ip, port, proto, null, result, seen);

        // If the original target was a domain (not a bare IP), record it as an asset — but
        // don't link it to the IP: naabu doesn't know the DNS record type/chain behind it
        // (could be a CNAME alias), only DNS-record-aware tools (dnsx) create domain_a/domain_aaaa.
        if (host != null && !host.isBlank() && !ScannerParserUtils.isIp(host)) {
            if (seen.add(host)) result.addAsset(new ParsedAsset(host, AssetType.DOMAIN, Map.of()));
        }
    }
}
