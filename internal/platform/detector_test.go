package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFrameworkAndPlatformTypeString(t *testing.T) {
	t.Parallel()

	if React.String() != "React" {
		t.Fatalf("unexpected framework string: %q", React.String())
	}
	if PlatformType(999).String() != "Unknown" {
		t.Fatal("expected unknown platform string")
	}
}

func TestDetect_EndToEnd(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "Express")
		_, _ = w.Write([]byte(`
<html>
<div data-reactroot></div>
<script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script>
<script>fetch('/api/users')</script>
</html>`))
	}))
	defer ts.Close()

	d := NewDetector(2 * time.Second)
	got, err := d.Detect(ts.URL)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if len(got.Frameworks) == 0 {
		t.Fatal("expected detected frameworks")
	}
	if got.PlatformType != Hybrid {
		t.Fatalf("expected Hybrid platform, got %s", got.PlatformType.String())
	}
	if len(got.ServerTech) == 0 {
		t.Fatal("expected server technologies")
	}
}

func TestDetectorHelpers(t *testing.T) {
	t.Parallel()

	d := NewDetector(2 * time.Second)
	detection := &Detection{
		Frameworks:     []FrameworkInfo{},
		ServerTech:     []string{},
		JavaScriptLibs: []LibraryInfo{},
	}

	headers := http.Header{}
	headers.Set("Server", "Django")
	headers.Set("X-Powered-By", "Express")
	d.detectFromHeaders(headers, detection)
	if len(detection.ServerTech) < 2 {
		t.Fatalf("expected server tech entries, got %+v", detection.ServerTech)
	}

	content := `
<script src="https://cdn.jsdelivr.net/npm/vue@3.4.0/dist/vue.global.js"></script>
<script src="https://unpkg.com/preact/dist/preact.min.js"></script>
<meta name="generator" content="wordpress" />
<link href="/wp-content/plugins/seo/plugin.js" />
<script>axios.get('/rest/users')</script>
`
	d.detectFromHTML(content, detection)
	d.detectJSFrameworks(content, detection)
	d.detectCMS(content, headers, detection)
	d.detectAPIEndpoints(content, detection)
	d.detectCDNs(content, detection)
	d.determinePlatformType(detection)

	if detection.PlatformType == UnknownPlatform {
		t.Fatal("expected a concrete platform type")
	}
	if len(detection.APIEndpoints) == 0 {
		t.Fatal("expected discovered API endpoints")
	}
	if !detection.hasFramework(Vue) {
		t.Fatal("expected Vue framework")
	}
	if detection.CMS == nil {
		t.Fatal("expected CMS detection")
	}
}

func TestVersionExtractionAndJSON(t *testing.T) {
	t.Parallel()

	d := NewDetector(2 * time.Second)
	if got := d.extractReactVersion(`react@18.2.0`); got != "18.2.0" {
		t.Fatalf("unexpected react version: %q", got)
	}
	if got := d.extractVueVersion(`Vue.version='3.4.0'`); got != "3.4.0" {
		t.Fatalf("unexpected vue version: %q", got)
	}
	if got := d.extractAngularVersion(`ng-version="17.0.0"`); got != "17.0.0" {
		t.Fatalf("unexpected angular version: %q", got)
	}
	if got := d.extractSvelteVersion(`svelte@4.2.3`); got != "4.2.3" {
		t.Fatalf("unexpected svelte version: %q", got)
	}

	detection := &Detection{PlatformType: SPA}
	b, err := detection.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON returned error: %v", err)
	}
	if !json.Valid(b) {
		t.Fatal("ToJSON output is not valid JSON")
	}
	if !detection.IsSPA() {
		t.Fatal("expected IsSPA=true")
	}
	if detection.IsStatic() {
		t.Fatal("expected IsStatic=false")
	}

	detection.PlatformType = StaticSite
	if !detection.IsStatic() {
		t.Fatal("expected IsStatic=true")
	}

	if !contains([]string{"a", "b"}, "a") {
		t.Fatal("contains should return true")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("contains should return false")
	}

	detection.Frameworks = []FrameworkInfo{{Name: "React", Confidence: 50}}
	detection.addFramework(React, "18.2.0", 90)
	if !strings.Contains(detection.Frameworks[0].Version, "18.2.0") {
		t.Fatalf("expected updated version, got %+v", detection.Frameworks[0])
	}
}
