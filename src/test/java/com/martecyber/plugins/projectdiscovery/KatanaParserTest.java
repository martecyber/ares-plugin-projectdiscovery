package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseContext;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link KatanaParser}: both the nested and flat JSONL shapes, the domain-scope gate
 *  (same-domain / subdomain-family / explicit-scope / filter-disabled), query-string stripping
 *  with per-endpoint param accumulation across repeated observations, and technology extraction
 *  in both its string and object forms. */
class KatanaParserTest {

    private final KatanaParser parser = new KatanaParser();

    private ParseResult parse(String jsonl) throws Exception {
        return parser.parse(jsonl.getBytes(StandardCharsets.UTF_8));
    }

    private ParseResult parse(String jsonl, ParseContext ctx) throws Exception {
        return parser.parse(jsonl.getBytes(StandardCharsets.UTF_8), ctx);
    }

    @Test
    void validateAcceptsBothNestedAndFlatShapes() {
        assertTrue(parser.validate("{\"request\":{\"endpoint\":\"https://a\"}}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate("{\"endpoint\":\"https://a\",\"source\":\"https://a\"}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"endpoint\":\"https://a\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void nestedFormatBuildsTheFullDomainWebappEndpointChain() throws Exception {
        ParseResult result = parse(
            "{\"request\":{\"endpoint\":\"https://example.com/admin\",\"source\":\"https://example.com/\"},"
            + "\"response\":{\"status_code\":200}}\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_APPLICATION) && a.getIdentifier().equals("https://example.com")));
        ParsedAsset endpoint = result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();
        assertEquals("https://example.com/admin", endpoint.getIdentifier());
        assertEquals(List.of(200), endpoint.getMetadata().get("statusCodes"));

        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_DOMAIN)
            && l.getFromIdentifier().equals("https://example.com") && l.getToIdentifier().equals("example.com")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_ENDPOINT)
            && l.getToIdentifier().equals("https://example.com/admin")));
    }

    @Test
    void flatFormatProducesTheSameChainAsNestedForEquivalentData() throws Exception {
        ParseResult result = parse("{\"endpoint\":\"https://example.com/admin\",\"source\":\"https://example.com/\",\"status_code\":200}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT) && a.getIdentifier().equals("https://example.com/admin")));
    }

    @Test
    void externalSourceIsDroppedByDefaultWithNoScopeContext() throws Exception {
        // Endpoint on example.com but discovered via a link from an unrelated external domain,
        // and no project-scope context supplied — Katana reports these even with -fs rdn active.
        ParseResult result = parse("{\"endpoint\":\"https://example.com/x\",\"source\":\"https://totally-different.org/\"}\n");
        assertTrue(result.getAssets().isEmpty());
    }

    @Test
    void externalSourceIsKeptWhenTheCallerDisablesTheFilter() throws Exception {
        ParseResult result = parse(
            "{\"endpoint\":\"https://example.com/x\",\"source\":\"https://totally-different.org/\"}\n",
            new ParseContext(Set.of(), true));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT)));
    }

    @Test
    void externalSourceIsKeptWhenItMatchesAnExplicitScopeDomain() throws Exception {
        ParseResult result = parse(
            "{\"endpoint\":\"https://example.com/x\",\"source\":\"https://totally-different.org/\"}\n",
            new ParseContext(Set.of("example.com"), false));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT)));
    }

    @Test
    void subdomainOfTheSourceIsKeptAsTheSameDomainFamily() throws Exception {
        ParseResult result = parse("{\"endpoint\":\"https://api.example.com/x\",\"source\":\"https://www.example.com/\"}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT)));
    }

    @Test
    void entryMissingSourceIsPermissivelyKept() throws Exception {
        // No source context at all → isSameDomainFamily's null-source branch is permissive.
        ParseResult result = parse("{\"endpoint\":\"https://example.com/x\"}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.WEB_ENDPOINT)));
    }

    @Test
    void endpointIdentifierStripsQueryAndParamsAreAccumulatedInMetadata() throws Exception {
        ParseResult result = parse("{\"endpoint\":\"https://example.com/search?q=test\",\"source\":\"https://example.com/\"}\n");
        ParsedAsset endpoint = result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();
        assertEquals("https://example.com/search", endpoint.getIdentifier());
        @SuppressWarnings("unchecked")
        Map<String, List<String>> params = (Map<String, List<String>>) endpoint.getMetadata().get("params");
        assertEquals(List.of("test"), params.get("q"));
    }

    @Test
    void repeatedObservationsOfTheSameEndpointMergeParamsStatusCodesAndSourcesWithoutDuplicating() throws Exception {
        ParseResult result = parse(
            "{\"endpoint\":\"https://example.com/search?q=a\",\"source\":\"https://example.com/\",\"status_code\":200}\n"
            + "{\"endpoint\":\"https://example.com/search?q=b\",\"source\":\"https://example.com/other\",\"status_code\":301}\n"
            + "{\"endpoint\":\"https://example.com/search?q=a\",\"source\":\"https://example.com/\",\"status_code\":200}\n");

        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).count());
        ParsedAsset endpoint = result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();

        @SuppressWarnings("unchecked")
        Map<String, List<String>> params = (Map<String, List<String>>) endpoint.getMetadata().get("params");
        assertEquals(List.of("a", "b"), params.get("q"));

        @SuppressWarnings("unchecked")
        List<Object> statusCodes = (List<Object>) endpoint.getMetadata().get("statusCodes");
        assertEquals(2, statusCodes.size());

        @SuppressWarnings("unchecked")
        List<Object> sources = (List<Object>) endpoint.getMetadata().get("sources");
        assertEquals(2, sources.size());
    }

    @Test
    void technologiesAreExtractedFromBothPlainStringsAndObjectsWithAName() throws Exception {
        ParseResult result = parse("""
            {"request":{"endpoint":"https://example.com/","source":"https://example.com/"},
             "response":{"technologies":["Nginx",{"name":"React"}]}}
            """.replace("\n", ""));

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.TECHNOLOGY) && a.getIdentifier().equals("Nginx")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.TECHNOLOGY) && a.getIdentifier().equals("React")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_TECHNOLOGY) && l.getToIdentifier().equals("Nginx")));
    }

    @Test
    void entryWithBlankEndpointIsSkipped() throws Exception {
        assertTrue(parse("{\"endpoint\":\"\",\"source\":\"https://example.com/\"}\n").getAssets().isEmpty());
    }

    @Test
    void entryWithAnUnparsableEndpointIsSkipped() throws Exception {
        assertTrue(parse("{\"endpoint\":\"not a url\",\"source\":\"https://example.com/\"}\n").getAssets().isEmpty());
    }
}
