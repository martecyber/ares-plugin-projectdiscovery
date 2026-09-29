package com.martecyber.plugins.projectdiscovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.detections.DetectionUrlReferenceParser;

import java.util.LinkedHashSet;
import java.util.Set;

/** Reads nuclei's {@code info.reference[]} — the one structured field nuclei embeds for
 *  documentation/vulnerability-reference URLs (as opposed to matched-at targets or
 *  request/response content, which are not documentation and would flood findings with junk
 *  "reference" URLs pointing at the client's own assets). See DetectionUrlReferenceParser's own
 *  doc (ares-core) for why this is scoped to one known field path. */
public class NucleiUrlReferenceParser implements DetectionUrlReferenceParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "nuclei"; }

    @Override
    public Set<String> extractUrls(String rawJson) {
        Set<String> out = new LinkedHashSet<>();
        try {
            JsonNode root = MAPPER.readTree(rawJson);
            JsonNode info = root.get("info");
            if (info == null) return out;
            JsonNode refs = info.get("reference");
            if (refs == null || !refs.isArray()) return out;
            refs.forEach(n -> {
                String v = n.asText(null);
                if (v != null && (v.startsWith("http://") || v.startsWith("https://"))) out.add(v.trim());
            });
        } catch (Exception ignored) {
            // Malformed rawData — treat as "nothing found", never fail the import over this.
        }
        return out;
    }
}
