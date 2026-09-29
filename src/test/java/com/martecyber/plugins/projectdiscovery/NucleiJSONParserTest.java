package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link NucleiJSONParser}'s asset-resolution branches: modern HTTP (host+scheme+port)
 *  vs. legacy HTTP (full URL in host) vs. non-HTTP findings, default-port suppression, the
 *  domain/ip/service chain for a named HTTP target, and the raw-data request/response strip. */
class NucleiJSONParserTest {

    private final NucleiJSONParser parser = new NucleiJSONParser();

    private ParseResult parse(String json) throws Exception {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateAcceptsJsonlAndJsonArrayShapes() {
        assertTrue(parser.validate("{\"template-id\":\"x\",\"info\":{}}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate("[{\"template-id\":\"x\"}]".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"foo\":\"bar\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void modernHttpFormatBuildsAWebApplicationSuppressingTheDefaultPort() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"exposed-panel\",\"info\":{\"name\":\"Exposed Panel\",\"severity\":\"medium\"},"
            + "\"host\":\"192.168.5.10\",\"scheme\":\"https\",\"port\":\"443\",\"matched-at\":\"https://192.168.5.10/admin\"}\n");

        ParsedAsset webapp = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_APPLICATION)).findFirst().orElseThrow();
        assertEquals("https://192.168.5.10", webapp.getIdentifier());

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Exposed Panel", d.getTitle());
        assertEquals("medium", d.getSeverity());
        assertEquals("https://192.168.5.10", d.getAssetIdentifier());
        assertTrue(d.getDescription().contains("Matched at: https://192.168.5.10/admin"));
    }

    @Test
    void legacyHttpFormatParsesTheFullUrlOutOfTheHostFieldKeepingANonDefaultPort() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"low\"},\"host\":\"https://10.0.0.5:8443/some/path\"}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://10.0.0.5:8443")));
    }

    @Test
    void httpFindingWithADomainHostAndSeparateIpBuildsTheFullChain() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"tls-issue\",\"info\":{\"name\":\"TLS issue\",\"severity\":\"high\"},"
            + "\"host\":\"example.com\",\"scheme\":\"https\",\"ip\":\"1.2.3.4\",\"port\":\"443\"}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("1.2.3.4:443/tcp")));

        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_DOMAIN)
            && l.getFromIdentifier().equals("https://example.com") && l.getToIdentifier().equals("example.com")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_A)
            && l.getFromIdentifier().equals("example.com") && l.getToIdentifier().equals("1.2.3.4")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_SERVICE)
            && l.getFromIdentifier().equals("https://example.com") && l.getToIdentifier().equals("1.2.3.4:443/tcp")));
    }

    @Test
    void nonHttpIpOnlyFindingResolvesTheDetectionToTheBareIpAssetNotTheHostAsset() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"open-service\",\"info\":{\"name\":\"Open service\",\"severity\":\"info\"},"
            + "\"host\":\"192.168.1.1\",\"type\":\"tcp\"}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.HOST) && a.getIdentifier().equals("host-192.168.1.1")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("192.168.1.1")));
        // resolveAsset returns the bare IP for this branch, not the "host-{ip}" HOST asset id.
        assertEquals("192.168.1.1", result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void nonHttpDomainFindingWithAPortEmitsAServiceAndReturnsItAsTheAssetIdentifier() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"smtp-check\",\"info\":{\"name\":\"SMTP\",\"severity\":\"low\"},"
            + "\"host\":\"mail.example.com\",\"ip\":\"5.6.7.8\",\"port\":\"25\",\"type\":\"tcp\"}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("mail.example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("5.6.7.8:25/tcp")));
        assertEquals("5.6.7.8:25/tcp", result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void nonHttpFindingWithOnlyAnIpFieldEmitsTheHostChainAndReturnsTheBareIp() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"info\"},\"ip\":\"9.9.9.9\",\"type\":\"tcp\"}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("9.9.9.9")));
        assertEquals("9.9.9.9", result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void findingWithNeitherHostNorIpIsAProjectLevelDetection() throws Exception {
        ParseResult result = parse("{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"info\"},\"type\":\"tcp\"}\n");
        assertNull(result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void referencesAreAppendedToTheDescription() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"info\",\"description\":\"Base desc.\","
            + "\"reference\":[\"https://a.example\",\"https://b.example\"]},\"host\":\"1.2.3.4\",\"type\":\"tcp\"}\n");
        String desc = result.getDetections().get(0).getDescription();
        assertTrue(desc.contains("Base desc."));
        assertTrue(desc.contains("- https://a.example"));
        assertTrue(desc.contains("- https://b.example"));
    }

    @Test
    void nameFallsBackToTemplateIdWhenInfoBlockIsMissing() throws Exception {
        ParseResult result = parse("{\"template-id\":\"my-template\",\"host\":\"1.2.3.4\",\"type\":\"tcp\"}\n");
        ParsedDetection d = result.getDetections().get(0);
        assertEquals("my-template", d.getTitle());
        assertEquals("info", d.getSeverity());
    }

    @Test
    void rawDataStripsRequestAndResponseFieldsButKeepsOtherFields() throws Exception {
        ParseResult result = parse(
            "{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"info\"},\"host\":\"1.2.3.4\",\"type\":\"tcp\","
            + "\"request\":\"GET / HTTP/1.1\",\"response\":\"HTTP/1.1 200 OK\",\"curl-command\":\"curl http://x\"}\n");
        String raw = result.getDetections().get(0).getRawData();
        assertFalse(raw.contains("GET / HTTP/1.1"));
        assertFalse(raw.contains("200 OK"));
        assertTrue(raw.contains("curl-command"));
    }

    @Test
    void parsesAJsonArrayInputTheSameAsJsonl() throws Exception {
        String json = "[{\"template-id\":\"a\",\"info\":{\"name\":\"A\",\"severity\":\"low\"},\"host\":\"1.2.3.4\",\"type\":\"tcp\"},"
            + "{\"template-id\":\"b\",\"info\":{\"name\":\"B\",\"severity\":\"low\"},\"host\":\"5.6.7.8\",\"type\":\"tcp\"}]";
        assertEquals(2, parse(json).getDetections().size());
    }

    @Test
    void invalidLineInAStreamDoesNotAbortTheRestOfTheFile() throws Exception {
        String jsonl = "{\"template-id\":\"a\",\"info\":{\"name\":\"A\",\"severity\":\"low\"},\"host\":\"1.2.3.4\",\"type\":\"tcp\"}\n"
            + "{not valid json\n"
            + "{\"template-id\":\"b\",\"info\":{\"name\":\"B\",\"severity\":\"low\"},\"host\":\"5.6.7.8\",\"type\":\"tcp\"}\n";
        ParseResult result = parse(jsonl);
        assertEquals(2, result.getDetections().size());
        assertFalse(result.getWarnings().isEmpty());
    }
}
