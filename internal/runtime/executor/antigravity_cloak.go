package executor

import (
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var defaultAntigravitySensitiveWords = []string{
	"proxy",
	"openclaw",
	"cliproxy",
	"cli-proxy",
}

func antigravitySensitiveWords(auth *cliproxyauth.Auth) []string {
	words := append([]string{}, defaultAntigravitySensitiveWords...)
	if auth == nil || auth.Attributes == nil {
		return words
	}
	raw := strings.TrimSpace(auth.Attributes["cloak_sensitive_words"])
	if raw == "" {
		return words
	}
	for _, w := range strings.Split(raw, ",") {
		w = strings.TrimSpace(w)
		if w != "" {
			words = append(words, w)
		}
	}
	return words
}

func obfuscateAntigravityPayload(payload []byte, matcher *SensitiveWordMatcher) []byte {
	if matcher == nil {
		return payload
	}

	// request.systemInstruction.parts[].text
	systemParts := gjson.GetBytes(payload, "request.systemInstruction.parts")
	if systemParts.Exists() && systemParts.IsArray() {
		systemParts.ForEach(func(idx, part gjson.Result) bool {
			text := part.Get("text")
			if text.Exists() {
				orig := text.String()
				obf := matcher.obfuscateText(orig)
				if obf != orig {
					path := "request.systemInstruction.parts." + idx.String() + ".text"
					payload, _ = sjson.SetBytes(payload, path, obf)
				}
			}
			return true
		})
	}

	// request.contents[].parts[].text
	contents := gjson.GetBytes(payload, "request.contents")
	if contents.Exists() && contents.IsArray() {
		contents.ForEach(func(ci, c gjson.Result) bool {
			parts := c.Get("parts")
			if !parts.Exists() || !parts.IsArray() {
				return true
			}
			parts.ForEach(func(pi, p gjson.Result) bool {
				text := p.Get("text")
				if text.Exists() {
					orig := text.String()
					obf := matcher.obfuscateText(orig)
					if obf != orig {
						path := "request.contents." + ci.String() + ".parts." + pi.String() + ".text"
						payload, _ = sjson.SetBytes(payload, path, obf)
					}
				}
				return true
			})
			return true
		})
	}

	return payload
}
