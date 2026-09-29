package com.martecyber.plugins.projectdiscovery;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class NucleiUrlReferenceParserTest {

    private final NucleiUrlReferenceParser parser = new NucleiUrlReferenceParser();

    @Test
    void toolIdIsNuclei() {
        assertEquals("nuclei", parser.getToolId());
    }

    @Test
    void extractsUrlsFromInfoReferenceArray() {
        String raw = """
            {"info":{"name":"Test","reference":["https://nvd.nist.gov/vuln/detail/CVE-2024-0001","https://example.com/advisory"]}}""";
        Set<String> urls = parser.extractUrls(raw);
        assertEquals(Set.of("https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "https://example.com/advisory"), urls);
    }

    @Test
    void ignoresNonHttpEntries() {
        String raw = """
            {"info":{"reference":["not-a-url","ftp://example.com/x","https://ok.example.com"]}}""";
        assertEquals(Set.of("https://ok.example.com"), parser.extractUrls(raw));
    }

    @Test
    void returnsEmptySetWhenInfoOrReferenceIsMissing() {
        assertTrue(parser.extractUrls("{}").isEmpty());
        assertTrue(parser.extractUrls("""
            {"info":{"name":"Test"}}""").isEmpty());
    }

    @Test
    void returnsEmptySetForMalformedJsonRatherThanThrowing() {
        assertTrue(parser.extractUrls("not json at all").isEmpty());
    }
}
