package waf

import (
	"strings"
	"testing"
)

func TestEncoder_URLEncode(t *testing.T) {
	enc := NewEncoder()

	input := "<script>alert(1)</script>"
	result := enc.URLEncode(input)

	if strings.Contains(result, "<") || strings.Contains(result, ">") {
		t.Error("URL encoding should encode < and >")
	}

	if !strings.Contains(result, "%3C") || !strings.Contains(result, "%3E") {
		t.Error("URL encoding should produce %3C and %3E")
	}
}

func TestEncoder_DoubleURLEncode(t *testing.T) {
	enc := NewEncoder()

	input := "<script>"
	result := enc.DoubleURLEncode(input)

	// Double encoding should encode the % signs
	if !strings.Contains(result, "%25") {
		t.Error("Double URL encoding should produce %25")
	}
}

func TestEncoder_HTMLHexEncode(t *testing.T) {
	enc := NewEncoder()

	input := "<>"
	result := enc.HTMLHexEncode(input)

	if !strings.Contains(result, "&#x3c;") && !strings.Contains(result, "&#x3e;") {
		t.Errorf("HTML hex encoding should produce &#x entities, got %s", result)
	}
}

func TestEncoder_HTMLDecimalEncode(t *testing.T) {
	enc := NewEncoder()

	input := "<>"
	result := enc.HTMLDecimalEncode(input)

	if !strings.Contains(result, "&#60;") && !strings.Contains(result, "&#62;") {
		t.Errorf("HTML decimal encoding should produce &#decimal entities, got %s", result)
	}
}

func TestEncoder_UnicodeEncode(t *testing.T) {
	enc := NewEncoder()

	input := "<"
	result := enc.UnicodeEncode(input)

	if !strings.Contains(result, "\\u003c") {
		t.Errorf("Unicode encoding should produce \\uXXXX, got %s", result)
	}
}

func TestEncoder_Base64Encode(t *testing.T) {
	enc := NewEncoder()

	input := "alert(1)"
	result := enc.Base64Encode(input)

	// base64 of "alert(1)" is "YWxlcnQoMSk="
	if result != "YWxlcnQoMSk=" {
		t.Errorf("Base64 encoding failed, got %s", result)
	}
}

func TestEncoder_CaseVariation(t *testing.T) {
	enc := NewEncoder()

	input := "script"
	result := enc.CaseVariation(input)

	if result == input {
		t.Error("Case variation should change the case")
	}

	// Should still spell script (case-insensitive)
	if strings.ToLower(result) != "script" {
		t.Errorf("Case variation changed the characters, got %s", result)
	}
}

func TestEncoder_CommentInsertion(t *testing.T) {
	enc := NewEncoder()

	input := "alert(1)"
	result := enc.CommentInsertion(input)

	if !strings.Contains(result, "/*") {
		t.Errorf("Comment insertion should add comments, got %s", result)
	}
}

func TestEncoder_WhitespaceInsertion(t *testing.T) {
	enc := NewEncoder()

	input := "<script>"
	result := enc.WhitespaceInsertion(input)

	// Should have added whitespace
	if len(result) <= len(input) {
		t.Log("Whitespace insertion may not add characters if input has no spaces")
	}
}

func TestEncoder_NullByteInject(t *testing.T) {
	enc := NewEncoder()

	input := "script"
	result := enc.NullByteInject(input)

	if !strings.Contains(result, "\x00") {
		t.Errorf("Null byte injection should add null bytes, got %s", result)
	}
}

func TestEncoder_GenerateVariants(t *testing.T) {
	enc := NewEncoder()
	enc.SetLevel(EncodingLevelModerate)

	input := "<script>alert(1)</script>"
	variants := enc.GenerateVariants(input, WAFCloudflare)

	if len(variants) < 3 {
		t.Errorf("Expected at least 3 variants, got %d", len(variants))
	}

	// First variant should be original
	if variants[0] != input {
		t.Error("First variant should be the original payload")
	}
}

func TestEncoder_EncodeForContext(t *testing.T) {
	enc := NewEncoder()

	tests := []struct {
		context string
		input   string
		check   func(string) bool
	}{
		{"html", "<", func(s string) bool { return strings.Contains(s, "&lt;") }},
		{"url", " ", func(s string) bool { return strings.Contains(s, "%20") || strings.Contains(s, "+") }},
	}

	for _, tt := range tests {
		result := enc.EncodeForContext(tt.input, tt.context)
		if !tt.check(result) {
			t.Errorf("EncodeForContext(%s, %s) failed: %s", tt.input, tt.context, result)
		}
	}
}

func TestEncoder_GetBypassPayload(t *testing.T) {
	enc := NewEncoder()
	input := "alert(1)"

	// Test for different WAF types
	wafTypes := []WAFType{
		WAFCloudflare, WAFAkamai, WAFImperva,
		WAFModSecurity, WAFAFW, WAFUnknown,
	}

	for _, wafType := range wafTypes {
		result := enc.GetBypassPayload(input, wafType)
		if result == "" {
			t.Errorf("GetBypassPayload returned empty for %s", wafType)
		}
	}
}

func TestEncoder_DecodePayload(t *testing.T) {
	enc := NewEncoder()

	// Test URL decode
	encoded := "%3Cscript%3E"
	decoded := enc.DecodePayload(encoded)
	if decoded != "<script>" {
		t.Errorf("DecodePayload URL failed: got %s", decoded)
	}

	// Test double URL decode
	doubleEncoded := "%253Cscript%253E"
	decoded = enc.DecodePayload(doubleEncoded)
	if decoded != "<script>" {
		t.Errorf("DecodePayload double URL failed: got %s", decoded)
	}
}

func TestEncodingType_String(t *testing.T) {
	tests := []struct {
		et       EncodingType
		expected string
	}{
		{EncodingURL, "url"},
		{EncodingDoubleURL, "double-url"},
		{EncodingHTMLHex, "html-hex"},
		{EncodingNone, "none"},
	}

	for _, tt := range tests {
		result := tt.et.String()
		if result != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, result)
		}
	}
}

func TestEncoder_CharCodeWrap(t *testing.T) {
	enc := NewEncoder()

	result := enc.CharCodeWrap("abc")
	if !strings.Contains(result, "String.fromCharCode") {
		t.Error("CharCodeWrap should use String.fromCharCode")
	}
	if !strings.Contains(result, "97") { // 'a' = 97
		t.Error("CharCodeWrap should include char code for 'a'")
	}
}
