package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the full configuration for an Aegis ATO/Exploit session
type Config struct {
	Target    string     `yaml:"target"`
	Instances []Instance `yaml:"instances"`
	scenarios []Scenario `yaml:"scenarios"` // Lowercase for now, maybe public later if needed
	Tasks     []Task     `yaml:"tasks"`     // Tasks to execute
}

// Instance defines a browser or HTTP client instance
type Instance struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"` // "browser" or "http"
	Headless bool              `yaml:"headless"`
	Cookies  []Cookie          `yaml:"cookies,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// Cookie represents a cookie to be set on an instance
type Cookie struct {
	Name   string `yaml:"name"`
	Value  string `yaml:"value"`
	Domain string `yaml:"domain"`
	Path   string `yaml:"path"`
}

// Scenario represents a high-level test case (e.g. "ATO via Session Fixation")
type Scenario struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Steps       []Task `yaml:"steps"`
}

// Task is a sequence of actions
type Task struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Actions     []Action `yaml:"actions"`
}

// Action represents a single operation performed by an instance
type Action struct {
	Instance string            `yaml:"instance"` // Name of the instance to use
	Type     string            `yaml:"type"`     // navigate, click, input, wait, eval, assert, screenshot
	Params   map[string]string `yaml:"params"`   // Dynamic params like url, selector, text, script, value
}

// Load reads and parses a YAML configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}
