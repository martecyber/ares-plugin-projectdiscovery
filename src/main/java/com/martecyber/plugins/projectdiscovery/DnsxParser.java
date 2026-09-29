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
import java.util.Map;
import java.util.Set;

/**
 * Parses dnsx JSONL output (dnsx -json -a -aaaa -cname -mx -ns -txt -ptr -soa -srv -caa).
 *
 * Example entry:
 * {"host":"sub.example.com","resolver":["8.8.8.8:53"],
 *  "a":["1.2.3.4"],"aaaa":["2001:db8::1"],
 *  "cname":["other.example.com"],"mx":[{"host":"mail.example.com","preference":10}],
 *  "ns":["ns1.example.com"],"txt":["v=spf1 ..."],
 *  "ptr":["reverse.example.com"],"soa":{"ns":"ns1.example.com","mbox":"admin.example.com"},
 *  "srv":[{"target":"sip.example.com","port":5060,"priority":10,"weight":20}],
 *  "caa":[{"flag":0,"tag":"issue","value":"letsencrypt.org"}],
 *  "status_code":"NOERROR","timestamp":"..."}
 *
 * Asset chains produced:
 *   DOMAIN --domain_a-----> IP   (+ HOST chain per IPv4)
 *   DOMAIN --domain_aaaa--> IP   (+ HOST chain per IPv6)
 *   DOMAIN --domain_cname-> DOMAIN
 *   DOMAIN --domain_mx----> DOMAIN  (mail exchange)
 *   DOMAIN --domain_ns----> DOMAIN  (nameserver)
 *   DOMAIN --domain_txt---> TEXT_DATA
 *   DOMAIN --domain_ptr---> DOMAIN  (PTR reverse lookup)
 *   DOMAIN --domain_soa---> DOMAIN  (SOA primary NS)
 *   DOMAIN --domain_caa---> DOMAIN  (CAA certification authority)
 *   DOMAIN --domain_srv---> SERVICE (target:port/proto)
 */
public class DnsxParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId()    { return "dnsx"; }
    @Override public String getDisplayName() { return "dnsx"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json", ".jsonl"}; }

    @Override
    public boolean validate(byte[] content) {
        String first = ScannerParserUtils.firstNonEmptyLine(content);
        // dnsx always has "resolver" field; httpx has "url" instead
        return first.startsWith("{") && first.contains("\"host\"") && first.contains("\"resolver\"");
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
        String host = node.path("host").asText(null);
        if (host == null || host.isBlank()) return;

        // Emit the queried domain
        if (seen.add(host)) result.addAsset(new ParsedAsset(host, AssetType.DOMAIN, Map.of()));

        // CNAME records → DOMAIN --domain_cname--> DOMAIN, chained in query order. Must run
        // before A/AAAA below: when the queried name is an alias, the A/AAAA records dnsx
        // reports for it actually belong to the last domain in the chain, not to the
        // originally queried name — attributing them to `host` would create a relationship
        // that skips over the CNAME target(s) entirely.
        String cnameTarget = host;
        JsonNode cnames = node.get("cname");
        if (cnames != null && cnames.isArray()) {
            String prev = host;
            for (JsonNode c : cnames) {
                String cname = stripDot(c.asText("").trim());
                if (cname.isBlank()) continue;
                if (seen.add(cname)) result.addAsset(new ParsedAsset(cname, AssetType.DOMAIN, Map.of()));
                result.addLink(prev, cname, AssetLinkType.DOMAIN_CNAME);
                prev = cname;
            }
            cnameTarget = prev;
        }
        final String aTarget = cnameTarget;

        // A records → IPv4 IP + host chain
        JsonNode aRecords = node.get("a");
        if (aRecords != null && aRecords.isArray()) {
            aRecords.forEach(a -> {
                String ip = a.asText("").trim();
                if (!ip.isBlank() && ScannerParserUtils.isIp(ip)) {
                    ScannerParserUtils.emitHostChain(ip, result, seen);
                    result.addLink(aTarget, ip, AssetLinkType.DOMAIN_A);
                }
            });
        }

        // AAAA records → IPv6 IP + host chain
        JsonNode aaaa = node.get("aaaa");
        if (aaaa != null && aaaa.isArray()) {
            aaaa.forEach(a -> {
                String ip = a.asText("").trim();
                if (!ip.isBlank() && ScannerParserUtils.isIpv6(ip)) {
                    ScannerParserUtils.emitHostChain(ip, result, seen);
                    result.addLink(aTarget, ip, AssetLinkType.DOMAIN_AAAA);
                }
            });
        }

        // MX records → {"host": "mail.example.com", "preference": 10}
        JsonNode mx = node.get("mx");
        if (mx != null && mx.isArray()) {
            mx.forEach(m -> {
                String mxHost = stripDot(m.path("host").asText("").trim());
                if (!mxHost.isBlank()) {
                    if (seen.add(mxHost)) result.addAsset(new ParsedAsset(mxHost, AssetType.DOMAIN, Map.of()));
                    result.addLink(host, mxHost, AssetLinkType.DOMAIN_MX);
                }
            });
        }

        // NS records → array of strings or objects
        JsonNode ns = node.get("ns");
        if (ns != null && ns.isArray()) {
            ns.forEach(n -> {
                String nsHost = stripDot(n.isTextual() ? n.asText("").trim() : n.path("host").asText("").trim());
                if (!nsHost.isBlank()) {
                    if (seen.add(nsHost)) result.addAsset(new ParsedAsset(nsHost, AssetType.DOMAIN, Map.of()));
                    result.addLink(host, nsHost, AssetLinkType.DOMAIN_NS);
                }
            });
        }

        // TXT records → TEXT_DATA assets
        JsonNode txt = node.get("txt");
        if (txt != null && txt.isArray()) {
            txt.forEach(t -> {
                String value = t.asText("").trim();
                if (!value.isBlank()) {
                    if (seen.add(value)) result.addAsset(new ParsedAsset(value, AssetType.TEXT_DATA, Map.of()));
                    result.addLink(host, value, AssetLinkType.DOMAIN_TXT);
                }
            });
        }

        // PTR records → array of domain strings
        JsonNode ptr = node.get("ptr");
        if (ptr != null && ptr.isArray()) {
            ptr.forEach(p -> {
                String ptrHost = stripDot(p.asText("").trim());
                if (!ptrHost.isBlank()) {
                    if (seen.add(ptrHost)) result.addAsset(new ParsedAsset(ptrHost, AssetType.DOMAIN, Map.of()));
                    result.addLink(host, ptrHost, AssetLinkType.DOMAIN_PTR);
                }
            });
        }

        // SOA record → {"ns": "ns1.example.com.", "mbox": "admin.example.com.", ...}
        JsonNode soa = node.get("soa");
        if (soa != null && soa.isObject()) {
            String soaNs = stripDot(soa.path("ns").asText("").trim());
            if (!soaNs.isBlank()) {
                if (seen.add(soaNs)) result.addAsset(new ParsedAsset(soaNs, AssetType.DOMAIN, Map.of()));
                result.addLink(host, soaNs, AssetLinkType.DOMAIN_SOA);
            }
        }

        // CAA records → [{"flag": 0, "tag": "issue", "value": "letsencrypt.org"}]
        JsonNode caa = node.get("caa");
        if (caa != null && caa.isArray()) {
            caa.forEach(c -> {
                String caaValue = c.path("value").asText("").trim();
                if (!caaValue.isBlank()) {
                    if (seen.add(caaValue)) result.addAsset(new ParsedAsset(caaValue, AssetType.DOMAIN, Map.of()));
                    result.addLink(host, caaValue, AssetLinkType.DOMAIN_CAA);
                }
            });
        }

        // SRV records → [{"target": "sip.example.com.", "port": 5060, ...}]
        // Protocol extracted from the queried SRV name (host field), e.g. _sip._tcp.example.com → tcp
        JsonNode srv = node.get("srv");
        if (srv != null && srv.isArray()) {
            String proto = srvProto(host);
            srv.forEach(s -> {
                String target = stripDot(s.path("target").asText("").trim());
                int port = s.path("port").asInt(0);
                if (!target.isBlank() && port > 0) {
                    String svcId = target + ":" + port + "/" + proto;
                    if (seen.add(svcId)) result.addAsset(new ParsedAsset(svcId, AssetType.SERVICE, Map.of()));
                    result.addLink(host, svcId, AssetLinkType.DOMAIN_SRV);
                }
            });
        }
    }

    /** Strips trailing DNS dot from a hostname. */
    private static String stripDot(String s) {
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }

    /** Extracts TCP/UDP from an SRV query name like _sip._tcp.example.com. Defaults to tcp. */
    private static String srvProto(String host) {
        String lower = host.toLowerCase();
        if (lower.contains("._udp.")) return "udp";
        return "tcp";
    }
}
