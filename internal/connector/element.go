package connector

import (
	"encoding/json"
	"fmt"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/go-rod/rod"
)

// Element wraps a DOM element controlled via the extension bridge.
// It provides methods compatible with rod.Element.
type Element struct {
	page     *Page
	selector string
}

// newElement creates a new Element wrapper.
func newElement(page *Page, selector string) *Element {
	return &Element{
		page:     page,
		selector: selector,
	}
}

// Click clicks the element.
func (e *Element) Click(opts ...func(*rod.Mouse)) error {
	result, err := e.page.connector.sendCommand(bridge.CmdClick, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("click: %s", result.Error)
	}
	return nil
}

// Text returns the element's text content.
func (e *Element) Text() (string, error) {
	result, err := e.page.connector.sendCommand(bridge.CmdGetElementText, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get text: %s", result.Error)
	}
	var data struct {
		Text string `json:"text"`
	}
	if err := decodeResult(result, &data); err != nil {
		return "", err
	}
	return data.Text, nil
}

// HTML returns the element's HTML content.
func (e *Element) HTML() (string, error) {
	result, err := e.page.connector.sendCommand(bridge.CmdGetElementHTML, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get html: %s", result.Error)
	}
	var data struct {
		HTML string `json:"html"`
	}
	if err := decodeResult(result, &data); err != nil {
		return "", err
	}
	return data.HTML, nil
}

// GetAttribute returns an attribute value.
func (e *Element) GetAttribute(name string) (string, error) {
	result, err := e.page.connector.sendCommand(bridge.CmdGetElementAttr, map[string]string{
		"selector":  e.selector,
		"attribute": name,
	}, e.page.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get attribute: %s", result.Error)
	}
	var data struct {
		Value *string `json:"value"`
	}
	if err := decodeResult(result, &data); err != nil {
		return "", err
	}
	if data.Value == nil {
		return "", fmt.Errorf("attribute not found: %s", name)
	}
	return *data.Value, nil
}

// SetAttribute sets an attribute value (via JS).
func (e *Element) SetAttribute(name, value string) error {
	script := fmt.Sprintf(`() => { document.querySelector('%s').setAttribute('%s', '%s'); }`,
		e.selector, name, value)
	result, err := e.page.connector.sendCommand(bridge.CmdEvaluate, map[string]string{
		"script": script,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("set attribute: %s", result.Error)
	}
	return nil
}

// Property returns a JavaScript property value.
func (e *Element) Property(name string) interface{} {
	script := fmt.Sprintf(`() => document.querySelector('%s')['%s']`, e.selector, name)
	result, err := e.page.connector.sendCommand(bridge.CmdEvaluate, map[string]string{
		"script": script,
	}, e.page.tabID)
	if err != nil {
		return nil
	}
	var data struct {
		Result interface{} `json:"result"`
	}
	decodeResult(result, &data)
	return data.Result
}

// Select selects options in a <select> element.
func (e *Element) Select(values ...string) error {
	for _, v := range values {
		result, err := e.page.connector.sendCommand(bridge.CmdSelect, map[string]string{
			"selector": e.selector,
			"value":    v,
		}, e.page.tabID)
		if err != nil {
			return err
		}
		if !result.Success {
			return fmt.Errorf("select: %s", result.Error)
		}
	}
	return nil
}

// Input inputs text into the element.
func (e *Element) Input(text string) error {
	result, err := e.page.connector.sendCommand(bridge.CmdFill, map[string]string{
		"selector": e.selector,
		"value":    text,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("input: %s", result.Error)
	}
	return nil
}

// Type types text character by character.
func (e *Element) Type(text string, opts ...func()) error {
	result, err := e.page.connector.sendCommand(bridge.CmdType, map[string]string{
		"selector": e.selector,
		"value":    text,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("type: %s", result.Error)
	}
	return nil
}

// Focus focuses the element.
func (e *Element) Focus() error {
	result, err := e.page.connector.sendCommand(bridge.CmdFocus, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("focus: %s", result.Error)
	}
	return nil
}

// Blur removes focus from the element.
func (e *Element) Blur() error {
	result, err := e.page.connector.sendCommand(bridge.CmdBlur, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("blur: %s", result.Error)
	}
	return nil
}

// ScrollIntoView scrolls the element into view.
func (e *Element) ScrollIntoView() error {
	result, err := e.page.connector.sendCommand(bridge.CmdScrollIntoView, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("scroll into view: %s", result.Error)
	}
	return nil
}

// Box represents a rectangular bounding box.
type Box struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// BoundingBox returns the element's bounding box.
func (e *Element) BoundingBox() (*Box, error) {
	result, err := e.page.connector.sendCommand(bridge.CmdEvaluate, map[string]string{
		"script": fmt.Sprintf(`() => { const el = document.querySelector('%s'); if (!el) return null; const r = el.getBoundingClientRect(); return {x:r.x,y:r.y,width:r.width,height:r.height}; }`, e.selector),
	}, e.page.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("bounding box: %s", result.Error)
	}
	var data struct {
		Result *Box `json:"result"`
	}
	if err := decodeResult(result, &data); err != nil {
		return nil, err
	}
	if data.Result == nil {
		return nil, fmt.Errorf("element not found: %s", e.selector)
	}
	return data.Result, nil
}

// Remove removes the element from the DOM (via JS).
func (e *Element) Remove() error {
	script := fmt.Sprintf(`() => document.querySelector('%s').remove()`, e.selector)
	result, err := e.page.connector.sendCommand(bridge.CmdEvaluate, map[string]string{
		"script": script,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("remove: %s", result.Error)
	}
	return nil
}

// WaitFor loads the element or waits for it to appear.
func (e *Element) WaitFor() error {
	result, err := e.page.connector.sendCommand(bridge.CmdWaitForSelector, map[string]string{
		"selector": e.selector,
	}, e.page.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("wait for element: %s", result.Error)
	}
	return nil
}

// decodeResult is a helper to unmarshal Result.Data into a struct.
func decodeResult(result *bridge.Result, v interface{}) error {
	if result.Data == nil {
		return nil
	}
	return json.Unmarshal(result.Data, v)
}
