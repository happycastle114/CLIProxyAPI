package executor

import (
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestAntigravityCloakConfigFromAuth_Defaults(t *testing.T) {
	mode, strict, words := antigravityCloakConfigFromAuth(nil)

	if mode != "auto" {
		t.Fatalf("mode = %q, want auto", mode)
	}
	if strict {
		t.Fatalf("strict = %v, want false", strict)
	}

	mustContain := []string{"proxy", "openclaw", "OpenClaw", "cliproxy", "cli-proxy"}
	for _, w := range mustContain {
		if !containsWord(words, w) {
			t.Fatalf("default words should contain %q, got=%v", w, words)
		}
	}
}

func TestAntigravityCloakConfigFromAuth_MergesCustomWords(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"cloak_mode":            "always",
			"cloak_strict_mode":     "true",
			"cloak_sensitive_words": "foo, bar ,OpenRouter",
		},
	}

	mode, strict, words := antigravityCloakConfigFromAuth(auth)

	if mode != "always" {
		t.Fatalf("mode = %q, want always", mode)
	}
	if !strict {
		t.Fatalf("strict = %v, want true", strict)
	}

	mustContain := []string{"proxy", "openclaw", "OpenClaw", "foo", "bar", "OpenRouter"}
	for _, w := range mustContain {
		if !containsWord(words, w) {
			t.Fatalf("merged words should contain %q, got=%v", w, words)
		}
	}
}

func TestObfuscateAntigravityPayload_AppliesToSystemAndContents(t *testing.T) {
	payload := []byte(`{
		"request": {
			"systemInstruction": {
				"parts": [
					{"text": "Use OpenClaw proxy safely"}
				]
			},
			"contents": [
				{
					"parts": [
						{"text": "openclaw should be obfuscated"}
					]
				}
			]
		}
	}`)

	matcher := buildSensitiveWordMatcher([]string{"openclaw", "OpenClaw", "proxy"})
	out := obfuscateAntigravityPayload(payload, matcher)

	outStr := string(out)
	if strings.Contains(outStr, "OpenClaw") || strings.Contains(outStr, "openclaw") || strings.Contains(outStr, "proxy") {
		t.Fatalf("expected sensitive words to be obfuscated, got: %s", outStr)
	}
	if outStr == string(payload) {
		t.Fatalf("payload should be modified by obfuscation")
	}
}

func containsWord(words []string, target string) bool {
	for _, w := range words {
		if w == target {
			return true
		}
	}
	return false
}
