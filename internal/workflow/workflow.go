// Package workflow provides YAML/JSON-based automation for security scanning
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/ato"
	"github.com/coppertone/bug-hunter/app/aegis/internal/waf"
	"github.com/coppertone/bug-hunter/app/aegis/internal/xss"
	"gopkg.in/yaml.v3"
)

// Workflow represents an automated scan workflow
type Workflow struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string            `json:"version,omitempty" yaml:"version,omitempty"`
	Author      string            `json:"author,omitempty" yaml:"author,omitempty"`
	Variables   map[string]string `json:"variables,omitempty" yaml:"variables,omitempty"`
	Steps       []Step            `json:"steps" yaml:"steps"`
	OnSuccess   []Action          `json:"on_success,omitempty" yaml:"on_success,omitempty"`
	OnFailure   []Action          `json:"on_failure,omitempty" yaml:"on_failure,omitempty"`
	Output      OutputConfig      `json:"output,omitempty" yaml:"output,omitempty"`
}

// Step represents a single step in the workflow
type Step struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Type        StepType          `json:"type" yaml:"type"`
	Config      StepConfig        `json:"config,omitempty" yaml:"config,omitempty"`
	Condition   string            `json:"condition,omitempty" yaml:"condition,omitempty"`
	ContinueOn  string            `json:"continue_on,omitempty" yaml:"continue_on,omitempty"` // "success", "failure", "always"
	Timeout     string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Retry       *RetryConfig      `json:"retry,omitempty" yaml:"retry,omitempty"`
	DependsOn   []string          `json:"depends_on,omitempty" yaml:"depends_on,omitempty"`
	Variables   map[string]string `json:"variables,omitempty" yaml:"variables,omitempty"`
}

// StepType represents the type of step
type StepType string

const (
	StepTypeScan       StepType = "scan"
	StepTypeWAFDetect  StepType = "waf_detect"
	StepTypeATOCheck   StepType = "ato_check"
	StepTypeCrawl      StepType = "crawl"
	StepTypeXSS        StepType = "xss"
	StepTypeInject     StepType = "inject"
	StepTypeExtract    StepType = "extract"
	StepTypeValidate   StepType = "validate"
	StepTypeReport     StepType = "report"
	StepTypeNotify     StepType = "notify"
	StepTypeScript     StepType = "script"
	StepTypeWait       StepType = "wait"
	StepTypeLoop       StepType = "loop"
	StepTypeParallel   StepType = "parallel"
)

// StepConfig holds configuration for a step
type StepConfig struct {
	// Target configuration
	Target  string   `json:"target,omitempty" yaml:"target,omitempty"`
	Targets []string `json:"targets,omitempty" yaml:"targets,omitempty"`

	// Scan options
	ScanType      string   `json:"scan_type,omitempty" yaml:"scan_type,omitempty"`
	MaxPages      int      `json:"max_pages,omitempty" yaml:"max_pages,omitempty"`
	MaxDepth      int      `json:"max_depth,omitempty" yaml:"max_depth,omitempty"`
	Workers       int      `json:"workers,omitempty" yaml:"workers,omitempty"`
	Timeout       string   `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	// WAF options
	WAFBypass      bool     `json:"waf_bypass,omitempty" yaml:"waf_bypass,omitempty"`
	WAFType        string   `json:"waf_type,omitempty" yaml:"waf_type,omitempty"`
	EncodingLevel  int      `json:"encoding_level,omitempty" yaml:"encoding_level,omitempty"`

	// XSS options
	ElementFocus   []string `json:"element_focus,omitempty" yaml:"element_focus,omitempty"`
	PayloadFile    string   `json:"payload_file,omitempty" yaml:"payload_file,omitempty"`
	CustomPayloads []string `json:"custom_payloads,omitempty" yaml:"custom_payloads,omitempty"`

	// Crawl options
	FollowRedirects bool              `json:"follow_redirects,omitempty" yaml:"follow_redirects,omitempty"`
	Headers         map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Cookies         map[string]string `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	SessionFile     string            `json:"session_file,omitempty" yaml:"session_file,omitempty"`

	// Inject options
	Selector  string   `json:"selector,omitempty" yaml:"selector,omitempty"`
	Payload   string   `json:"payload,omitempty" yaml:"payload,omitempty"`
	Payloads  []string `json:"payloads,omitempty" yaml:"payloads,omitempty"`
	Event     string   `json:"event,omitempty" yaml:"event,omitempty"`

	// Extract options
	Patterns []string `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	Fields   []string `json:"fields,omitempty" yaml:"fields,omitempty"`

	// Report options
	Format   string `json:"format,omitempty" yaml:"format,omitempty"` // json, html, md
	OutputTo string `json:"output_to,omitempty" yaml:"output_to,omitempty"`
	Template string `json:"template,omitempty" yaml:"template,omitempty"`

	// Notify options
	Webhook  string `json:"webhook,omitempty" yaml:"webhook,omitempty"`
	Email    string `json:"email,omitempty" yaml:"email,omitempty"`
	Slack    string `json:"slack,omitempty" yaml:"slack,omitempty"`

	// Script options
	Script  string   `json:"script,omitempty" yaml:"script,omitempty"`
	Command string   `json:"command,omitempty" yaml:"command,omitempty"`
	Args    []string `json:"args,omitempty" yaml:"args,omitempty"`

	// Loop options
	Items    []string `json:"items,omitempty" yaml:"items,omitempty"`
	ItemsRef string   `json:"items_ref,omitempty" yaml:"items_ref,omitempty"`
	SubSteps []Step   `json:"sub_steps,omitempty" yaml:"sub_steps,omitempty"`

	// Parallel options
	ParallelSteps []Step `json:"parallel_steps,omitempty" yaml:"parallel_steps,omitempty"`
	MaxParallel   int    `json:"max_parallel,omitempty" yaml:"max_parallel,omitempty"`

	// Wait options
	Duration string `json:"duration,omitempty" yaml:"duration,omitempty"`
	Until    string `json:"until,omitempty" yaml:"until,omitempty"`
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxAttempts int    `json:"max_attempts" yaml:"max_attempts"`
	Delay       string `json:"delay,omitempty" yaml:"delay,omitempty"`
	BackoffMult float64 `json:"backoff_mult,omitempty" yaml:"backoff_mult,omitempty"`
}

// Action represents an action to take on workflow events
type Action struct {
	Type    string            `json:"type" yaml:"type"`
	Config  map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	Directory string   `json:"directory,omitempty" yaml:"directory,omitempty"`
	Formats   []string `json:"formats,omitempty" yaml:"formats,omitempty"`
	Compress  bool     `json:"compress,omitempty" yaml:"compress,omitempty"`
}

// StepResult holds the result of a step execution
type StepResult struct {
	StepID    string        `json:"step_id"`
	StepName  string        `json:"step_name"`
	Status    string        `json:"status"` // success, failure, skipped
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Output    interface{}   `json:"output,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// WorkflowResult holds the complete workflow execution result
type WorkflowResult struct {
	WorkflowName string        `json:"workflow_name"`
	Status       string        `json:"status"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	Steps        []StepResult  `json:"steps"`
	Findings     interface{}   `json:"findings,omitempty"`
}

// Runner executes workflows
type Runner struct {
	workflow *Workflow
	ctx      context.Context
	results  []StepResult
	vars     map[string]interface{}
	verbose  bool
}

// NewRunner creates a new workflow runner
func NewRunner(workflow *Workflow, opts ...RunnerOption) *Runner {
	r := &Runner{
		workflow: workflow,
		vars:     make(map[string]interface{}),
		verbose:  false,
	}

	// Copy workflow variables
	for k, v := range workflow.Variables {
		r.vars[k] = v
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// RunnerOption configures the runner
type RunnerOption func(*Runner)

// WithVerbose enables verbose output
func WithVerbose(verbose bool) RunnerOption {
	return func(r *Runner) {
		r.verbose = verbose
	}
}

// WithVariables sets additional variables
func WithVariables(vars map[string]string) RunnerOption {
	return func(r *Runner) {
		for k, v := range vars {
			r.vars[k] = v
		}
	}
}

// LoadWorkflow loads a workflow from a file
func LoadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var workflow Workflow

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &workflow); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			if err := json.Unmarshal(data, &workflow); err != nil {
				return nil, fmt.Errorf("failed to parse workflow (tried YAML and JSON)")
			}
		}
	}

	return &workflow, nil
}

// Run executes the workflow
func (r *Runner) Run(ctx context.Context) (*WorkflowResult, error) {
	r.ctx = ctx
	startTime := time.Now()

	result := &WorkflowResult{
		WorkflowName: r.workflow.Name,
		StartTime:    startTime,
		Status:       "success",
	}

	if r.verbose {
		fmt.Printf("\n=== Starting Workflow: %s ===\n\n", r.workflow.Name)
	}

	// Execute steps
	for _, step := range r.workflow.Steps {
		select {
		case <-ctx.Done():
			result.Status = "cancelled"
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(startTime)
			return result, ctx.Err()
		default:
		}

		stepResult := r.executeStep(step)
		r.results = append(r.results, stepResult)
		result.Steps = append(result.Steps, stepResult)

		if stepResult.Status == "failure" {
			continueOn := strings.ToLower(step.ContinueOn)
			if continueOn != "failure" && continueOn != "always" {
				result.Status = "failure"
				break
			}
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	// Execute on_success or on_failure actions
	if result.Status == "success" && len(r.workflow.OnSuccess) > 0 {
		r.executeActions(r.workflow.OnSuccess)
	} else if result.Status == "failure" && len(r.workflow.OnFailure) > 0 {
		r.executeActions(r.workflow.OnFailure)
	}

	if r.verbose {
		fmt.Printf("\n=== Workflow Complete: %s (Status: %s, Duration: %s) ===\n",
			r.workflow.Name, result.Status, result.Duration)
	}

	return result, nil
}

// executeStep executes a single step
func (r *Runner) executeStep(step Step) StepResult {
	startTime := time.Now()
	result := StepResult{
		StepID:    step.ID,
		StepName:  step.Name,
		StartTime: startTime,
	}

	if r.verbose {
		fmt.Printf("[%s] Starting step: %s\n", step.ID, step.Name)
	}

	// Check dependencies
	if !r.checkDependencies(step.DependsOn) {
		result.Status = "skipped"
		result.Error = "dependencies not met"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(startTime)
		return result
	}

	// Parse timeout
	timeout := 5 * time.Minute // default
	if step.Timeout != "" {
		if d, err := time.ParseDuration(step.Timeout); err == nil {
			timeout = d
		}
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()

	// Execute based on step type
	var output interface{}
	var err error

	switch step.Type {
	case StepTypeScan:
		output, err = r.executeScan(ctx, step.Config)
	case StepTypeWAFDetect:
		output, err = r.executeWAFDetect(ctx, step.Config)
	case StepTypeATOCheck:
		output, err = r.executeATOCheck(ctx, step.Config)
	case StepTypeCrawl:
		output, err = r.executeCrawl(ctx, step.Config)
	case StepTypeXSS:
		output, err = r.executeXSS(ctx, step.Config)
	case StepTypeInject:
		output, err = r.executeInject(ctx, step.Config)
	case StepTypeExtract:
		output, err = r.executeExtract(ctx, step.Config)
	case StepTypeReport:
		output, err = r.executeReport(ctx, step.Config)
	case StepTypeWait:
		err = r.executeWait(ctx, step.Config)
	case StepTypeLoop:
		output, err = r.executeLoop(ctx, step)
	case StepTypeParallel:
		output, err = r.executeParallel(ctx, step)
	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	if err != nil {
		result.Status = "failure"
		result.Error = err.Error()
	} else {
		result.Status = "success"
		result.Output = output
	}

	// Store output in variables
	if step.ID != "" && output != nil {
		r.vars[step.ID+"_output"] = output
		r.vars[step.ID+"_status"] = result.Status
	}

	if r.verbose {
		fmt.Printf("[%s] Completed: %s (Status: %s, Duration: %s)\n",
			step.ID, step.Name, result.Status, result.Duration)
	}

	return result
}

func (r *Runner) checkDependencies(deps []string) bool {
	for _, dep := range deps {
		status, ok := r.vars[dep+"_status"]
		if !ok || status != "success" {
			return false
		}
	}
	return true
}

func (r *Runner) executeActions(actions []Action) {
	for _, action := range actions {
		switch action.Type {
		case "notify":
			// Implement notification
		case "log":
			if msg, ok := action.Config["message"]; ok {
				fmt.Println(msg)
			}
		}
	}
}

// executeScan performs a combined scan using WAF detection, ATO, and XSS
func (r *Runner) executeScan(ctx context.Context, config StepConfig) (interface{}, error) {
	target := r.resolveVariable(config.Target)

	result := map[string]interface{}{
		"target": target,
		"status": "completed",
	}

	// Run WAF detection if WAF bypass is enabled
	if config.WAFBypass {
		wafResult, err := r.executeWAFDetect(ctx, config)
		if err == nil {
			result["waf"] = wafResult
		}
	}

	// Run XSS scan
	xssResult, err := r.executeXSS(ctx, config)
	if err == nil {
		result["xss"] = xssResult
	}

	// Run ATO check if not disabled
	atoResult, err := r.executeATOCheck(ctx, config)
	if err == nil {
		result["ato"] = atoResult
	}

	return result, nil
}

// executeWAFDetect performs WAF fingerprinting
func (r *Runner) executeWAFDetect(ctx context.Context, config StepConfig) (interface{}, error) {
	target := r.resolveVariable(config.Target)

	// Parse timeout
	timeout := 30 * time.Second
	if config.Timeout != "" {
		if d, err := time.ParseDuration(config.Timeout); err == nil {
			timeout = d
		}
	}

	detector := waf.NewDetector(waf.WithTimeout(timeout))
	detection, err := detector.DetectWithContext(ctx, target)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"target":           target,
		"waf_type":         detection.WAFType.String(),
		"confidence":       detection.Confidence,
		"evidence":         detection.Evidence,
		"bypass_strategies": waf.GetBypassStrategies(detection.WAFType),
	}

	if r.verbose {
		fmt.Printf("  WAF Detected: %s (confidence: %d%%)\n", detection.WAFType.String(), detection.Confidence)
	}

	return result, nil
}

// executeATOCheck performs Account Takeover vulnerability detection
func (r *Runner) executeATOCheck(ctx context.Context, config StepConfig) (interface{}, error) {
	target := r.resolveVariable(config.Target)

	// Parse timeout
	timeout := 30 * time.Second
	if config.Timeout != "" {
		if d, err := time.ParseDuration(config.Timeout); err == nil {
			timeout = d
		}
	}

	detector := ato.NewDetector(ato.WithTimeout(timeout))
	findings := detector.DetectAllWithContext(ctx, target)

	result := map[string]interface{}{
		"target":         target,
		"findings_count": len(findings),
		"findings":       findings,
	}

	if r.verbose {
		fmt.Printf("  ATO Check: found %d potential issues\n", len(findings))
	}

	return result, nil
}

// executeCrawl performs web crawling (placeholder - needs crawler integration)
func (r *Runner) executeCrawl(ctx context.Context, config StepConfig) (interface{}, error) {
	target := r.resolveVariable(config.Target)

	// This would integrate with the actual crawler module
	// For now, return the target as a single page
	result := map[string]interface{}{
		"target":    target,
		"pages":     []string{target},
		"max_depth": config.MaxDepth,
		"max_pages": config.MaxPages,
	}

	if r.verbose {
		fmt.Printf("  Crawl target: %s (max_depth: %d)\n", target, config.MaxDepth)
	}

	return result, nil
}

// executeXSS performs XSS vulnerability scanning with WAF bypass
func (r *Runner) executeXSS(ctx context.Context, config StepConfig) (interface{}, error) {
	target := r.resolveVariable(config.Target)

	// Build scanner options
	opts := []xss.EnhancedScannerOption{
		xss.WithVerbose(r.verbose),
	}

	// WAF bypass options
	if config.WAFBypass {
		opts = append(opts, xss.WithWAFBypass(true))
	}

	// WAF type if specified
	if config.WAFType != "" {
		wafType := parseWAFType(config.WAFType)
		opts = append(opts, xss.WithWAFType(wafType))
	}

	// Encoding level
	if config.EncodingLevel > 0 {
		level := waf.EncodingLevel(config.EncodingLevel)
		opts = append(opts, xss.WithEncodingLevel(level))
	}

	// Element focus
	if len(config.ElementFocus) > 0 {
		elements := parseElementTypes(config.ElementFocus)
		opts = append(opts, xss.WithElements(elements...))
	}

	// Create scanner
	scanner, err := xss.NewEnhancedScanner(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create XSS scanner: %w", err)
	}
	defer scanner.Close()

	// Run scan
	scanResult, err := scanner.ScanWithBypassContext(ctx, target)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"target":          target,
		"findings_count":  len(scanResult.Findings),
		"findings":        scanResult.Findings,
		"tested_payloads": scanResult.TestedPayloads,
		"duration":        scanResult.Duration.String(),
	}

	if scanResult.WAFDetection != nil {
		result["waf_detected"] = scanResult.WAFDetection.WAFType.String()
	}

	if r.verbose {
		fmt.Printf("  XSS Scan: tested %d payloads, found %d issues\n",
			scanResult.TestedPayloads, len(scanResult.Findings))
	}

	return result, nil
}

// executeInject performs payload injection (requires browser - placeholder)
func (r *Runner) executeInject(ctx context.Context, config StepConfig) (interface{}, error) {
	selector := r.resolveVariable(config.Selector)
	payload := r.resolveVariable(config.Payload)

	// This would integrate with browser/injector module
	result := map[string]interface{}{
		"selector": selector,
		"payload":  payload,
		"status":   "requires_browser",
	}

	if r.verbose {
		fmt.Printf("  Inject: selector=%s\n", selector)
	}

	return result, nil
}

// executeExtract extracts data using patterns (placeholder)
func (r *Runner) executeExtract(ctx context.Context, config StepConfig) (interface{}, error) {
	result := map[string]interface{}{
		"patterns": config.Patterns,
		"fields":   config.Fields,
		"matches":  []string{},
	}

	return result, nil
}

// executeReport generates a scan report
func (r *Runner) executeReport(ctx context.Context, config StepConfig) (interface{}, error) {
	format := config.Format
	if format == "" {
		format = "json"
	}

	outputTo := r.resolveVariable(config.OutputTo)

	// Collect all findings from previous steps
	allFindings := make(map[string]interface{})
	for key, val := range r.vars {
		if strings.HasSuffix(key, "_output") {
			allFindings[strings.TrimSuffix(key, "_output")] = val
		}
	}

	report := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"format":       format,
		"output":       outputTo,
		"results":      allFindings,
	}

	// Write report if output path specified
	if outputTo != "" {
		var data []byte
		var err error

		switch format {
		case "json":
			data, err = json.MarshalIndent(report, "", "  ")
		case "yaml":
			data, err = yaml.Marshal(report)
		default:
			data, err = json.MarshalIndent(report, "", "  ")
		}

		if err != nil {
			return nil, err
		}

		// Ensure directory exists
		dir := filepath.Dir(outputTo)
		if dir != "" && dir != "." {
			os.MkdirAll(dir, 0755)
		}

		if err := os.WriteFile(outputTo, data, 0644); err != nil {
			return nil, err
		}

		if r.verbose {
			fmt.Printf("  Report written to: %s\n", outputTo)
		}
	}

	return report, nil
}

func (r *Runner) executeWait(ctx context.Context, config StepConfig) error {
	if config.Duration != "" {
		d, err := time.ParseDuration(config.Duration)
		if err != nil {
			return err
		}
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *Runner) executeLoop(ctx context.Context, step Step) (interface{}, error) {
	var results []StepResult

	items := step.Config.Items
	if step.Config.ItemsRef != "" {
		if v, ok := r.vars[step.Config.ItemsRef]; ok {
			if arr, ok := v.([]string); ok {
				items = arr
			}
		}
	}

	for _, item := range items {
		r.vars["loop_item"] = item
		for _, subStep := range step.Config.SubSteps {
			result := r.executeStep(subStep)
			results = append(results, result)
		}
	}

	return results, nil
}

func (r *Runner) executeParallel(ctx context.Context, step Step) (interface{}, error) {
	results := make([]StepResult, len(step.Config.ParallelSteps))
	done := make(chan struct{}, len(step.Config.ParallelSteps))

	for i, pStep := range step.Config.ParallelSteps {
		go func(idx int, s Step) {
			results[idx] = r.executeStep(s)
			done <- struct{}{}
		}(i, pStep)
	}

	for range step.Config.ParallelSteps {
		select {
		case <-done:
		case <-ctx.Done():
			return results, ctx.Err()
		}
	}

	return results, nil
}

// SaveResult saves the workflow result to a file
func (r *Runner) SaveResult(result *WorkflowResult, path string) error {
	var data []byte
	var err error

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(result, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(result)
	default:
		data, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// resolveVariable replaces {{variable}} placeholders with actual values
func (r *Runner) resolveVariable(s string) string {
	if s == "" {
		return s
	}

	result := s
	for key, val := range r.vars {
		placeholder := "{{" + key + "}}"
		if strVal, ok := val.(string); ok {
			result = strings.ReplaceAll(result, placeholder, strVal)
		}
	}

	return result
}

// parseWAFType converts a string to waf.WAFType
func parseWAFType(s string) waf.WAFType {
	mapping := map[string]waf.WAFType{
		"cloudflare":  waf.WAFCloudflare,
		"akamai":      waf.WAFAkamai,
		"imperva":     waf.WAFImperva,
		"modsecurity": waf.WAFModSecurity,
		"aws-waf":     waf.WAFAFW,
		"sucuri":      waf.WAFSuccuri,
		"barracuda":   waf.WAFBarracuda,
		"citrix-adc":  waf.WAFCitrix,
		"nginx-naxsi": waf.WAFNginx,
		"stackpath":   waf.WAFStackPath,
		"incapsula":   waf.WAFIncapsula,
		"f5-big-ip":   waf.WAFBIG_IP_ASM,
		"fortiweb":    waf.WAFFortiWeb,
		"radware":     waf.WAFRadware,
		"wordfence":   waf.WAFWordfence,
		"kona":        waf.WAFKona,
	}

	if t, ok := mapping[strings.ToLower(s)]; ok {
		return t
	}
	return waf.WAFUnknown
}

// parseElementTypes converts strings to waf.ElementType slice
func parseElementTypes(elements []string) []waf.ElementType {
	mapping := map[string]waf.ElementType{
		"script": waf.ElementScript,
		"img":    waf.ElementImg,
		"svg":    waf.ElementSVG,
		"div":    waf.ElementDiv,
		"span":   waf.ElementSpan,
		"a":      waf.ElementA,
		"iframe": waf.ElementIframe,
		"input":  waf.ElementInput,
		"form":   waf.ElementForm,
	}

	var result []waf.ElementType
	for _, e := range elements {
		if t, ok := mapping[strings.ToLower(e)]; ok {
			result = append(result, t)
		}
	}

	if len(result) == 0 {
		// Default to common elements
		return []waf.ElementType{waf.ElementScript, waf.ElementImg, waf.ElementSVG, waf.ElementDiv}
	}

	return result
}

// Validate checks the workflow configuration for errors
func (w *Workflow) Validate() error {
	if w.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	if len(w.Steps) == 0 {
		return fmt.Errorf("workflow must have at least one step")
	}

	stepIDs := make(map[string]bool)
	for i, step := range w.Steps {
		if step.ID == "" {
			return fmt.Errorf("step %d: id is required", i)
		}

		if stepIDs[step.ID] {
			return fmt.Errorf("step %d: duplicate step id '%s'", i, step.ID)
		}
		stepIDs[step.ID] = true

		if step.Type == "" {
			return fmt.Errorf("step %d (%s): type is required", i, step.ID)
		}

		// Validate dependencies exist
		for _, dep := range step.DependsOn {
			if !stepIDs[dep] {
				// Check if it's a forward reference (not allowed)
				found := false
				for _, s := range w.Steps {
					if s.ID == dep {
						found = true
						break
					}
				}
				if found {
					return fmt.Errorf("step %d (%s): depends on '%s' which is defined later (forward references not allowed)", i, step.ID, dep)
				}
				return fmt.Errorf("step %d (%s): depends on unknown step '%s'", i, step.ID, dep)
			}
		}
	}

	return nil
}

// GetStepByID returns a step by its ID
func (w *Workflow) GetStepByID(id string) *Step {
	for i := range w.Steps {
		if w.Steps[i].ID == id {
			return &w.Steps[i]
		}
	}
	return nil
}

// GetFindings collects all vulnerability findings from the result
func (r *WorkflowResult) GetFindings() []interface{} {
	var findings []interface{}

	for _, step := range r.Steps {
		if step.Output == nil {
			continue
		}

		output, ok := step.Output.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for findings in various formats
		if f, ok := output["findings"]; ok {
			if fList, ok := f.([]interface{}); ok {
				findings = append(findings, fList...)
			}
		}
	}

	return findings
}

// HasFailures returns true if any step failed
func (r *WorkflowResult) HasFailures() bool {
	for _, step := range r.Steps {
		if step.Status == "failure" {
			return true
		}
	}
	return false
}

// GetFailedSteps returns all failed step results
func (r *WorkflowResult) GetFailedSteps() []StepResult {
	var failed []StepResult
	for _, step := range r.Steps {
		if step.Status == "failure" {
			failed = append(failed, step)
		}
	}
	return failed
}
