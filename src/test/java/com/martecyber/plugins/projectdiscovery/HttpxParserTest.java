package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link HttpxParser}: the full domain→ip→service→webapp chain when a resolved IP is
 *  present, graceful degradation when it isn't (probed by bare IP, or IP missing entirely), and
 *  the technology-link fan-out. */
class HttpxParserTest {

    private final HttpxParser parser = new HttpxParser();

    private ParseResult parse(String jsonl) throws Exception {
        return parser.parse(jsonl.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresUrlAndStatusCode() {
        assertTrue(parser.validate("{\"url\":\"https://a\",\"status_code\":200}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"url\":\"https://a\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void fullChainWithResolvedIpDomainAndTech() throws Exception {
        ParseResult result = parse("""
            {"url":"https://example.com","input":"example.com","host":"1.2.3.4","port":"443",
             "scheme":"https","status_code":200,"title":"Example","webserver":"nginx",
             "tech":["Nginx","PHP"]}
            """.replace("\n", ""));

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("1.2.3.4")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("1.2.3.4:443/tcp")));

        ParsedAsset webapp = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_APPLICATION)).findFirst().orElseThrow();
        assertEquals("https://example.com", webapp.getIdentifier());
        assertEquals("Example", webapp.getMetadata().get("title"));
        assertEquals("nginx", webapp.getMetadata().get("server"));
        assertEquals(200, webapp.getMetadata().get("statusCode"));

        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_SERVICE)
            && l.getFromIdentifier().equals("https://example.com") && l.getToIdentifier().equals("1.2.3.4:443/tcp")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_DOMAIN)
            && l.getFromIdentifier().equals("https://example.com") && l.getToIdentifier().equals("example.com")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_TECHNOLOGY)
            && l.getToIdentifier().equals("Nginx")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.TECHNOLOGY) && a.getIdentifier().equals("PHP")));
    }

    @Test
    void probingByBareIpEmitsNoDomainAsset() throws Exception {
        ParseResult result = parse("{\"url\":\"http://1.2.3.4\",\"input\":\"1.2.3.4\",\"host\":\"1.2.3.4\",\"port\":\"80\",\"status_code\":200}\n");
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.DOMAIN)));
        assertTrue(result.getLinks().stream().noneMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_DOMAIN)));
    }

    @Test
    void missingResolvedIpStillEmitsTheWebApplicationWithoutAServiceLink() throws Exception {
        ParseResult result = parse("{\"url\":\"https://example.com\",\"status_code\":200}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION)));
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.IP)));
        assertTrue(result.getLinks().stream().noneMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_SERVICE)));
    }

    @Test
    void malformedPortIsIgnoredWithoutFailingTheWholeEntry() throws Exception {
        ParseResult result = parse("{\"url\":\"https://example.com\",\"host\":\"1.2.3.4\",\"port\":\"not-a-number\",\"status_code\":200}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION)));
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.SERVICE)));
    }

    @Test
    void entryWithoutAUrlIsSkipped() throws Exception {
        ParseResult result = parse("{\"status_code\":200}\n{\"url\":\"https://example.com\",\"status_code\":200}\n");
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_APPLICATION)).count());
    }
}
