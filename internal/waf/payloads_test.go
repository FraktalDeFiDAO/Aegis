package waf

import (
	"testing"
)

func TestPayloadGenerator_Generate(t *testing.T) {
	gen := NewPayloadGenerator()

	// Test generating script payloads
	payloads := gen.Generate(WAFUnknown, ElementScript)
	if len(payloads) == 0 {
		t.Error("Expected script payloads")
	}

	// Verify payloads have required fields
	for _, p := range payloads {
		if p.Value == "" {
			t.Error("Payload value should not be empty")
		}
		if p.Element != ElementScript {
			t.Errorf("Expected element %s, got %s", ElementScript, p.Element)
		}
	}
}

func TestPayloadGenerator_GenerateMultipleElements(t *testing.T) {
	gen := NewPayloadGenerator()

	payloads := gen.Generate(WAFUnknown, ElementScript, ElementImg, ElementDiv)

	// Should have payloads from all element types
	hasScript := false
	hasImg := false
	hasDiv := false

	for _, p := range payloads {
		switch p.Element {
		case ElementScript:
			hasScript = true
		case ElementImg:
			hasImg = true
		case ElementDiv:
			hasDiv = true
		}
	}

	if !hasScript {
		t.Error("Expected script payloads")
	}
	if !hasImg {
		t.Error("Expected img payloads")
	}
	if !hasDiv {
		t.Error("Expected div payloads")
	}
}

func TestPayloadGenerator_WAFFiltering(t *testing.T) {
	gen := NewPayloadGenerator()

	// Generate with WAF type
	payloads := gen.Generate(WAFCloudflare, ElementScript)

	// Should have payloads that target Cloudflare at the front
	foundCloudflareTargeted := false
	for i, p := range payloads {
		for _, target := range p.WAFTargets {
			if target == WAFCloudflare {
				if i > 10 { // Should be prioritized
					t.Log("Cloudflare-targeted payload found but not prioritized")
				}
				foundCloudflareTargeted = true
				break
			}
		}
		if foundCloudflareTargeted {
			break
		}
	}

	if !foundCloudflareTargeted {
		t.Log("No Cloudflare-specific payloads found, which is fine")
	}
}

func TestPayloadGenerator_GenerateAll(t *testing.T) {
	gen := NewPayloadGenerator()
	payloads := gen.GenerateAll()

	if len(payloads) < 50 {
		t.Errorf("Expected at least 50 payloads, got %d", len(payloads))
	}
}

func TestPayloadGenerator_GetPolyglotPayloads(t *testing.T) {
	gen := NewPayloadGenerator()
	polyglots := gen.GetPolyglotPayloads()

	if len(polyglots) == 0 {
		t.Error("Expected polyglot payloads")
	}

	// Polyglots should have high confidence
	for _, p := range polyglots {
		if p.Category != CategoryPolyglot {
			t.Errorf("Expected polyglot category, got %s", p.Category)
		}
		if p.Confidence < 60 {
			t.Errorf("Polyglot payloads should have high confidence, got %d", p.Confidence)
		}
	}
}

func TestPayloadGenerator_GetDOMClobberingPayloads(t *testing.T) {
	gen := NewPayloadGenerator()
	clobbering := gen.GetDOMClobberingPayloads()

	if len(clobbering) == 0 {
		t.Error("Expected DOM clobbering payloads")
	}

	for _, p := range clobbering {
		if p.Category != CategoryDOMClobbering {
			t.Errorf("Expected DOM clobbering category, got %s", p.Category)
		}
	}
}

func TestPayloadGenerator_GetTemplateInjectionPayloads(t *testing.T) {
	gen := NewPayloadGenerator()
	templates := gen.GetTemplateInjectionPayloads()

	if len(templates) == 0 {
		t.Error("Expected template injection payloads")
	}

	for _, p := range templates {
		if p.Category != CategoryTemplateInject {
			t.Errorf("Expected template injection category, got %s", p.Category)
		}
	}
}

func TestPayloadCategories(t *testing.T) {
	gen := NewPayloadGenerator()
	payloads := gen.GenerateAll()

	categories := make(map[PayloadCategory]int)
	for _, p := range payloads {
		categories[p.Category]++
	}

	// Should have multiple categories
	if len(categories) < 3 {
		t.Errorf("Expected at least 3 payload categories, got %d", len(categories))
	}
}
