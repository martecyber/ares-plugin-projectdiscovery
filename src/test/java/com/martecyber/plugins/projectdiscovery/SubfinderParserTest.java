package com.martecyber.plugins.projectdiscovery;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link SubfinderParser}'s dual plain-text/JSONL input handling — format is picked
 *  entirely from whether the first non-blank line starts with '{'. */
class SubfinderParserTest {

    private final SubfinderParser parser = new SubfinderParser();

    @Test
    void validateAcceptsPlainHostnameLines() {
        assertTrue(parser.validate("sub.example.com\n".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("not a hostname line\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void validateAcceptsJsonlWithHostAndSourceOrInputOrType() {
        assertTrue(parser.validate("{\"host\":\"a.example.com\",\"source\":\"certspotter\"}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"host\":\"a.example.com\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parsesPlainTextOneDomainPerLineDeduplicated() throws Exception {
        ParseResult result = parser.parse("""
            sub1.example.com
            sub2.example.com
            sub1.example.com
            """.getBytes(StandardCharsets.UTF_8));

        assertEquals(2, result.getAssets().size());
        assertTrue(result.getAssets().stream().allMatch(a -> a.getType().equals(AssetType.DOMAIN)));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("sub1.example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("sub2.example.com")));
    }

    @Test
    void plainTextSkipsBlankAndSpaceContainingLines() throws Exception {
        ParseResult result = parser.parse("\n  \nnot a domain line\nsub.example.com\n".getBytes(StandardCharsets.UTF_8));
        assertEquals(1, result.getAssets().size());
        assertEquals("sub.example.com", result.getAssets().get(0).getIdentifier());
    }

    @Test
    void parsesJsonlExtractingOnlyTheHostField() throws Exception {
        ParseResult result = parser.parse((
            "{\"host\":\"a.example.com\",\"input\":\"example.com\",\"source\":\"certspotter\"}\n"
            + "{\"host\":\"b.example.com\",\"input\":\"example.com\",\"source\":\"crtsh\"}\n").getBytes(StandardCharsets.UTF_8));

        assertEquals(2, result.getAssets().size());
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("a.example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getIdentifier().equals("b.example.com")));
    }

    @Test
    void jsonlDeduplicatesRepeatedHostsAcrossDifferentSources() throws Exception {
        ParseResult result = parser.parse((
            "{\"host\":\"a.example.com\",\"source\":\"certspotter\"}\n"
            + "{\"host\":\"a.example.com\",\"source\":\"crtsh\"}\n").getBytes(StandardCharsets.UTF_8));
        assertEquals(1, result.getAssets().size());
    }

    @Test
    void jsonlEntryMissingHostFieldIsSkippedWithoutThrowing() throws Exception {
        ParseResult result = parser.parse("{\"source\":\"certspotter\"}\n{\"host\":\"a.example.com\",\"source\":\"crtsh\"}\n".getBytes(StandardCharsets.UTF_8));
        assertEquals(1, result.getAssets().size());
    }
}
