package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedAssetLink;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers {@link DnsxParser}: the record-type-specific relationship each JSONL entry produces
 * (domain_a/aaaa/cname/mx/ns/txt/ptr/soa/caa/srv), the CNAME-chain reattribution of A/AAAA records
 * to the chain's final target (not the originally-queried name), trailing-dot stripping, and the
 * malformed-line resilience the importer relies on.
 */
class DnsxParserTest {

    private final DnsxParser parser = new DnsxParser();

    private ParseResult parse(String jsonl) throws Exception {
        return parser.parse(jsonl.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresHostAndResolverFieldsOnTheFirstLine() {
        assertTrue(parser.validate("{\"host\":\"a\",\"resolver\":[\"8.8.8.8:53\"]}".getBytes(StandardCharsets.UTF_8)));
        // httpx output has "url" instead of "resolver" — must not be mistaken for dnsx.
        assertFalse(parser.validate("{\"host\":\"a\",\"url\":\"http://a\"}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("not json".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aRecordEmitsIpAndHostChainLinkedFromTheQueriedDomain() throws Exception {
        ParseResult result = parse("""
            {"host":"example.com","resolver":["8.8.8.8:53"],"a":["1.2.3.4"]}
            """);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DOMAIN) && a.getIdentifier().equals("example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("1.2.3.4")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.HOST) && a.getIdentifier().equals("host-1.2.3.4")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getFromIdentifier().equals("example.com")
            && l.getToIdentifier().equals("1.2.3.4") && l.getLinkType().equals(AssetLinkType.DOMAIN_A)));
    }

    @Test
    void aaaaRecordIsRejectedIfNotAnActualIpv6Address() throws Exception {
        // A malformed/garbage "aaaa" entry must not produce a bogus IP asset.
        ParseResult result = parse("""
            {"host":"example.com","resolver":["8.8.8.8:53"],"aaaa":["not-an-ipv6"]}
            """);
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.IP)));
        assertTrue(result.getLinks().isEmpty());
    }

    @Test
    void aaaaRecordEmitsIpv6HostChainWithDomainAaaaLink() throws Exception {
        ParseResult result = parse("""
            {"host":"example.com","resolver":["8.8.8.8:53"],"aaaa":["2001:db8::1"]}
            """);
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.IP) && a.getIdentifier().equals("2001:db8::1")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_AAAA)
            && l.getFromIdentifier().equals("example.com") && l.getToIdentifier().equals("2001:db8::1")));
    }

    @Test
    void cnameChainReattributesARecordsToTheFinalChainTargetNotTheQueriedName() throws Exception {
        // www.example.com -> cdn.example.com -> edge.cdn.net, with the A record belonging to
        // the alias chain's actual endpoint (edge.cdn.net), not to the originally queried name.
        // dnsx's JSONL format is genuinely one JSON object per physical line — forEachJsonLine
        // only recognizes a line that itself starts with "{", so the fixture must stay unwrapped.
        ParseResult result = parse(
            "{\"host\":\"www.example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"cname\":[\"cdn.example.com.\",\"edge.cdn.net.\"],\"a\":[\"9.9.9.9\"]}\n");

        List<ParsedAssetLink> links = result.getLinks();
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_CNAME)
            && l.getFromIdentifier().equals("www.example.com") && l.getToIdentifier().equals("cdn.example.com")));
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_CNAME)
            && l.getFromIdentifier().equals("cdn.example.com") && l.getToIdentifier().equals("edge.cdn.net")));
        // The A record is attributed to the LAST domain in the chain, not to "www.example.com".
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_A)
            && l.getFromIdentifier().equals("edge.cdn.net") && l.getToIdentifier().equals("9.9.9.9")));
        assertTrue(links.stream().noneMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_A)
            && l.getFromIdentifier().equals("www.example.com")));

        // Trailing DNS dots are stripped from every emitted CNAME target.
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("cdn.example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("edge.cdn.net")));
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getIdentifier().endsWith(".")));
    }

    @Test
    void mxNsTxtPtrRecordsProduceTheirOwnLinkTypesFromTheQueriedName() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"mx\":[{\"host\":\"mail.example.com.\",\"preference\":10}],"
            + "\"ns\":[\"ns1.example.com.\"],"
            + "\"txt\":[\"v=spf1 include:_spf.example.com ~all\"],"
            + "\"ptr\":[\"reverse.example.com.\"]}\n");

        List<ParsedAssetLink> links = result.getLinks();
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_MX)
            && l.getFromIdentifier().equals("example.com") && l.getToIdentifier().equals("mail.example.com")));
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_NS)
            && l.getToIdentifier().equals("ns1.example.com")));
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_TXT)
            && l.getToIdentifier().equals("v=spf1 include:_spf.example.com ~all")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.TEXT_DATA)));
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_PTR)
            && l.getToIdentifier().equals("reverse.example.com")));
    }

    @Test
    void nsRecordAcceptsBothPlainStringsAndObjectEntries() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"ns\":[\"ns1.example.com.\",{\"host\":\"ns2.example.com.\"}]}\n");
        List<ParsedAssetLink> links = result.getLinks();
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_NS) && l.getToIdentifier().equals("ns1.example.com")));
        assertTrue(links.stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_NS) && l.getToIdentifier().equals("ns2.example.com")));
    }

    @Test
    void soaRecordLinksToItsPrimaryNameserver() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"soa\":{\"ns\":\"ns1.example.com.\",\"mbox\":\"admin.example.com.\"}}\n");
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_SOA)
            && l.getFromIdentifier().equals("example.com") && l.getToIdentifier().equals("ns1.example.com")));
    }

    @Test
    void caaRecordLinksToTheCertificateAuthorityValue() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"caa\":[{\"flag\":0,\"tag\":\"issue\",\"value\":\"letsencrypt.org\"}]}\n");
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_CAA)
            && l.getToIdentifier().equals("letsencrypt.org")));
    }

    @Test
    void srvRecordBuildsTargetPortServiceIdAndInfersProtocolFromTheQueriedName() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"_sip._udp.example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"srv\":[{\"target\":\"sip.example.com.\",\"port\":5060,\"priority\":10,\"weight\":20}]}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE)
            && a.getIdentifier().equals("sip.example.com:5060/udp")));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.DOMAIN_SRV)
            && l.getToIdentifier().equals("sip.example.com:5060/udp")));
    }

    @Test
    void srvRecordDefaultsToTcpWhenQueriedNameHasNoUdpMarker() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"_sip._tcp.example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"srv\":[{\"target\":\"sip.example.com.\",\"port\":5060}]}\n");
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("sip.example.com:5060/tcp")));
    }

    @Test
    void srvRecordWithoutAPositivePortIsSkipped() throws Exception {
        ParseResult result = parse(
            "{\"host\":\"_sip._tcp.example.com\",\"resolver\":[\"8.8.8.8:53\"],"
            + "\"srv\":[{\"target\":\"sip.example.com.\",\"port\":0}]}\n");
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.SERVICE)));
    }

    @Test
    void entriesWithoutAHostFieldAreIgnored() throws Exception {
        ParseResult result = parse("""
            {"resolver":["8.8.8.8:53"],"a":["1.2.3.4"]}
            """);
        assertTrue(result.getAssets().isEmpty());
        assertTrue(result.getLinks().isEmpty());
    }

    @Test
    void malformedLineIsSkippedWithAWarningInsteadOfAbortingTheWholeFile() throws Exception {
        // The second line is truncated/invalid JSON — DnsxParser.processEntry must catch its own
        // failure per-line (see ScannerParserUtils.forEachJsonLine's own test for why this must
        // be the caller's responsibility) so the third, well-formed line still comes through.
        ParseResult result = parse("""
            {"host":"good1.example.com","resolver":["8.8.8.8:53"],"a":["1.1.1.1"]}
            {"host":"broken.example.com","resolver":["8.8.8.8:53"],"a":[1,2,
            {"host":"good2.example.com","resolver":["8.8.8.8:53"],"a":["2.2.2.2"]}
            """);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("good1.example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("good2.example.com")));
        assertFalse(result.getWarnings().isEmpty());
    }

    @Test
    void multipleEntriesShareAssetsAcrossLinesWithoutDuplicating() throws Exception {
        ParseResult result = parse("""
            {"host":"example.com","resolver":["8.8.8.8:53"],"a":["1.2.3.4"]}
            {"host":"example.com","resolver":["8.8.8.8:53"],"a":["1.2.3.4"]}
            """);
        assertEquals(1, result.getAssets().stream().filter(a -> a.getIdentifier().equals("example.com")).count());
        assertEquals(1, result.getAssets().stream().filter(a -> a.getIdentifier().equals("1.2.3.4")).count());
    }
}
