package registry

import "testing"

func TestExtractVersionFromString(t *testing.T) {
    cases := []struct{
        in string
        want string
    }{
        {"v1.2.3", "v1.2.3"},
        {"1.2.3", "1.2.3"},
        {"release v2.6.0 (stable)", "v2.6.0"},
        {"refs/tags/v3.4.5", "v3.4.5"},
        {"refs/tags/2.6.0", "2.6.0"},
        {"latest", ""},
        {"", ""},
        // Ensure we don't accept non-semver plain strings
        {"buildkit.dockerfile.v0", ""},
        {"nightly", ""},
    }
    for _, tc := range cases {
        got := extractVersionFromString(tc.in)
        if got != tc.want {
            t.Fatalf("extractVersionFromString(%q)=%q; want %q", tc.in, got, tc.want)
        }
    }
}

func TestPickVersionFromAnnotationsIgnoresTitleDescription(t *testing.T) {
    ann := map[string]string{
        "org.opencontainers.image.title":       "Apache NiFi",
        "org.opencontainers.image.description": "Based on OpenJDK v21.0.8 and Debian",
    }
    if v := pickVersionFromAnnotations(ann); v != "" {
        t.Fatalf("expected no version from title/description, got %q", v)
    }
    ann["org.opencontainers.image.version"] = "2.6.0"
    if v := pickVersionFromAnnotations(ann); v != "2.6.0" {
        t.Fatalf("expected version 2.6.0 from explicit annotation, got %q", v)
    }
}
