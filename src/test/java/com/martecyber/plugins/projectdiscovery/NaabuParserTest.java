package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link NaabuParser}: the IP→interface→service chain, the domain-asset-without-a-link
 *  behavior for a hostname target, and the validate() heuristic that must reject masscan's
 *  "ports" array shape (both tools emit a flat {@code "ip"} field). */
class NaabuParserTest {

    private final NaabuParser parser = new NaabuParser();

    private ParseResult parse(String jsonl) throws Exception {
        return parser.parse(jsonl.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateAcceptsNaabuShapeAndRejectsMasscanShape() {
        assertTrue(parser.validate("{\"ip\":\"1.2.3.4\",\"port\":80,\"protocol\":\"tcp\"}".getBytes(StandardCharsets.UTF_8)));
        // Masscan uses a "ports" array instead of a flat "port" field.
        assertFalse(parser.validate("{\"ip\":\"1.2.3.4\",\"ports\":[{\"port\":80}]}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("not json".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void emitsIpInterfaceServiceChainForAValidEntry() throws Exception {
        ParseResult result = parse("{\"ip\":\"10.0.0.1\",\"port\":22,\"protocol\":\"tcp\",\"host\":\"10.0.0.1\"}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("10.0.0.1")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("10.0.0.1:22/tcp")));
        // The target itself was a bare IP — no separate DOMAIN asset should be emitted for it.
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.DOMAIN)));
    }

    @Test
    void emitsADomainAssetWithNoLinkWhenTheOriginalTargetWasAHostname() throws Exception {
        ParseResult result = parse("{\"ip\":\"10.0.0.1\",\"port\":443,\"protocol\":\"tcp\",\"host\":\"sub.example.com\"}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("sub.example.com")));
        // naabu doesn't know the DNS record type behind the hostname — no link to the IP.
        assertTrue(result.getLinks().stream().noneMatch(l -> l.getFromIdentifier().equals("sub.example.com")));
    }

    @Test
    void entryWithoutAValidIpOrPositivePortIsSkipped() throws Exception {
        assertTrue(parse("{\"ip\":\"not-an-ip\",\"port\":80,\"protocol\":\"tcp\"}\n").getAssets().isEmpty());
        assertTrue(parse("{\"ip\":\"10.0.0.1\",\"port\":0,\"protocol\":\"tcp\"}\n").getAssets().isEmpty());
    }
}
