package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/config"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const elementActionTimeout = 5 * time.Second

type Runner struct {
	Config    *config.Config
	Instances map[string]*rod.Page    // Holds browser pages key=instanceName
	Browsers  map[string]*rod.Browser // Holds browser controllers
	Launchers []*launcher.Launcher    // To cleanup
	Variables map[string]string       // Key-value store for extracted data
}

func New(cfg *config.Config) *Runner {
	return &Runner{
		Config:    cfg,
		Instances: make(map[string]*rod.Page),
		Browsers:  make(map[string]*rod.Browser),
		Launchers: make([]*launcher.Launcher, 0),
		Variables: make(map[string]string),
	}
}

func (r *Runner) RunAll() error {
	defer r.cleanup()

	// 1. Initialize Instances
	if err := r.initInstances(); err != nil {
		return fmt.Errorf("failed to init instances: %w", err)
	}

	// 2. Execute Tasks
	for _, task := range r.Config.Tasks {
		fmt.Printf("Running Task: %s\n", task.Name)
		if err := r.executeTask(task); err != nil {
			fmt.Printf("Error executing task %s: %v\n", task.Name, err)
			return err
		}
	}
	return nil
}

func (r *Runner) initInstances() error {
	for _, instCfg := range r.Config.Instances {
		l := launcher.New().
			Headless(instCfg.Headless).
			Set("no-sandbox", "true").
			Set("disable-gpu", "true") 

		// Prefer system chromium if available to avoid missing internal libraries in container
		if path, err := exec.LookPath("chromium"); err == nil {
			l.Bin(path)
		} else if path, err := exec.LookPath("google-chrome"); err == nil {
			l.Bin(path)
		} else if path, err := exec.LookPath("chromium-browser"); err == nil {
			l.Bin(path)
		}
		
		u, err := l.Launch()
		if err != nil {
			// Try to provide more context
			return fmt.Errorf("failed to launch browser for instance '%s': %w", instCfg.Name, err)
		}
		r.Launchers = append(r.Launchers, l)

		browser := rod.New().ControlURL(u).MustConnect()
		r.Browsers[instCfg.Name] = browser

		var page *rod.Page
		if instCfg.Type == "browser" {
			incognitoBrowser, err := browser.Incognito()
			if err != nil {
				return err
			}
			page = incognitoBrowser.MustPage()
		} else {
			page = browser.MustPage()
		}

		if len(instCfg.Cookies) > 0 {
			cookies := make([]*proto.NetworkCookieParam, len(instCfg.Cookies))
			for i, c := range instCfg.Cookies {
				cookies[i] = &proto.NetworkCookieParam{
					Name:   c.Name,
					Value:  c.Value,
					Domain: c.Domain,
					Path:   c.Path,
				}
			}
			if err := page.SetCookies(cookies); err != nil {
				return fmt.Errorf("failed to set cookies for %s: %w", instCfg.Name, err)
			}
		}

		r.Instances[instCfg.Name] = page
	}
	return nil
}

func (r *Runner) executeTask(task config.Task) error {
	for _, action := range task.Actions {
		page, ok := r.Instances[action.Instance]
		if !ok {
			return fmt.Errorf("instance '%s' not found for action %s", action.Instance, action.Type)
		}

		// Interpolate params
		params := make(map[string]string)
		for k, v := range action.Params {
			params[k] = r.interpolate(v)
		}

		switch action.Type {
		case "navigate":
			url := params["url"]
			if url == "" {
				return fmt.Errorf("missing 'url' param")
			}
			if err := page.Navigate(url); err != nil {
				return err
			}
			if err := page.WaitLoad(); err != nil {
				return err
			}

		case "click":
			selector := params["selector"]
			if selector == "" {
				return fmt.Errorf("missing 'selector' param")
			}
			el, err := page.Timeout(elementActionTimeout).Element(selector)
			if err != nil {
				return fmt.Errorf("element not found: %s", selector)
			}
			if err := el.Click(proto.InputMouseButtonLeft); err != nil {
				return err
			}

		case "input":
			selector := params["selector"]
			value := params["value"]
			if selector == "" {
				return fmt.Errorf("missing 'selector' param")
			}
			el, err := page.Timeout(elementActionTimeout).Element(selector)
			if err != nil {
				return fmt.Errorf("element not found: %s", selector)
			}
			if err := el.Input(value); err != nil {
				return err
			}
			
		case "submit":
			// Helper to press enter
			selector := params["selector"]
			if selector != "" {
				el, err := page.Timeout(elementActionTimeout).Element(selector)
				if err != nil {
					return fmt.Errorf("element not found: %s", selector)
				}
				if err := el.Focus(); err != nil {
					return err
				}
				if err := page.Keyboard.Press(input.Enter); err != nil {
					return err
				}
			} else {
				// Just press enter on current focus
				if err := page.Keyboard.Press(input.Enter); err != nil {
					return err
				}
			}

		case "wait":
			durationStr := params["duration"]
			duration, _ := time.ParseDuration(durationStr)
			if duration == 0 {
				duration = 1 * time.Second
			}
			time.Sleep(duration)

		case "eval":
			script := params["script"]
			res, err := page.Eval(script)
			if err != nil {
				return err
			}
			fmt.Printf("[%s] Eval: %v\n", action.Instance, res.Value)
			
			// Optional capture of eval result
			if varName := params["variable"]; varName != "" {
				r.Variables[varName] = fmt.Sprintf("%v", res.Value)
			}

		case "extract":
			selector := params["selector"]
			varName := params["variable"]
			attribute := params["attribute"]
			if selector == "" || varName == "" {
				return fmt.Errorf("missing 'selector' or 'variable' param for extract")
			}
			
			el, err := page.Timeout(elementActionTimeout).Element(selector)
			if err != nil {
				return fmt.Errorf("element not found: %s", selector)
			}
			
			var val string
			if attribute != "" {
				attr, err := el.Attribute(attribute)
				if err != nil {
					return err
				}
				if attr != nil {
					val = *attr
				}
			} else {
				val, err = el.Text()
				if err != nil {
					return err
				}
			}
			r.Variables[varName] = val
			fmt.Printf("Extracted variable %s = %s\n", varName, val)

		case "assert": 
			selector := params["selector"]
			expected := params["text"]
			contains := params["contains"]
			
			if selector != "" {
				el, err := page.Timeout(elementActionTimeout).Element(selector)
				if err != nil {
					return fmt.Errorf("element not found: %s", selector)
				}
				text, err := el.Text()
				if err != nil {
					return err
				}
				
				if expected != "" && text != expected {
					return fmt.Errorf("assertion failed: expected '%s', got '%s'", expected, text)
				}
				if contains != "" && !strings.Contains(text, contains) {
					return fmt.Errorf("assertion failed: text '%s' does not contain '%s'", text, contains)
				}
			}

		case "screenshot":
			path := params["path"]
			if path == "" {
				path = fmt.Sprintf("screenshot_%s_%d.png", action.Instance, time.Now().Unix())
			}
			data, err := page.Screenshot(true, nil)
			if err != nil {
				return err
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				return err
			}
			fmt.Printf("Screenshot saved to %s\n", path)

		default:
			return fmt.Errorf("unknown action type: %s", action.Type)
		}
	}
	return nil
}

func (r *Runner) cleanup() {
	for _, b := range r.Browsers {
		_ = b.Close()
	}
	for _, l := range r.Launchers {
		l.Cleanup()
	}
}

// interpolate replaces {{var}} with values from r.Variables
func (r *Runner) interpolate(input string) string {
	for k, v := range r.Variables {
		placeholder := "{{" + k + "}}"
		input = strings.ReplaceAll(input, placeholder, v)
	}
	return input
}
