package bridge

import "testing"

func TestOriginChecksParseHostsAndNeverUseUnsafePrefixes(t *testing.T) {
	for _, test := range []struct {
		origin           string
		local, extension bool
	}{
		{"", false, false}, {"x", false, false}, {"http://127.0.0.1", true, false},
		{"http://localhost:9876", true, false}, {"https://[::1]:9876", true, false},
		{"http://localhost.attacker.test", false, false}, {"https://127.0.0.1.attacker.test", false, false},
		{"http://localhost@attacker.test", false, false}, {"http://localhost/path", false, false},
		{"chrome-extension://abcdefghijklmnopabcdefghijklmnop", false, true},
		{"moz-extension://test-uuid", false, true}, {"chrome-extension:", false, false},
		{"chrome-extension://fake/path", false, false},
	} {
		if got := isLocalOrigin(test.origin); got != test.local {
			t.Errorf("local(%q)=%v", test.origin, got)
		}
		if got := isExtensionOrigin(test.origin); got != test.extension {
			t.Errorf("extension(%q)=%v", test.origin, got)
		}
	}
}
