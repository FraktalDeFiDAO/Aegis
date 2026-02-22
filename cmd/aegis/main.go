package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/api"
	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/intel"
	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
	"github.com/coppertone/bug-hunter/app/aegis/internal/recon"
	"github.com/coppertone/bug-hunter/app/aegis/internal/scanner"
	"github.com/coppertone/bug-hunter/app/aegis/internal/scrape"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/go-rod/rod"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

var (
	log        = logger.New()
	sessionKey []byte
)

func main() {
	root := &cobra.Command{
		Use:   "aegis",
		Short: "Project Aegis orchestration",
		Long:  "Control the authenticated crawler, mirroring, and audit workflow.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if scrapeFlag {
				return runScrapeScope(cmd, args, scrapeOpts)
			}
			return cmd.Help()
		},
	}

	root.PersistentFlags().BytesHexVar(&sessionKey, "key", nil, "32-byte hex-encoded encryption key for session file")
	root.PersistentFlags().BoolVar(&scrapeFlag, "scrape-scope", false, "Scrape all in-scope targets (requires <projectDir> <scopeConfig>)")
	root.PersistentFlags().StringVar(&scrapeConfigPath, "scrape-config", "", "Scrape configuration file (YAML)")
	bindScrapeFlags(root.PersistentFlags(), &scrapeOpts)

	root.AddCommand(authCmd(), crawlCmd(), scanCmd(), apiCmd(), benchCmd(), intelCmd(), reconCmd(), scrapeScopeCmd(), exploitCmd(), screenshotCmd(), rendercheckCmd())

	if err := root.Execute(); err != nil {
		log.Error("Execution failed", "error", err)
		os.Exit(1)
	}
}

var (
	scrapeFlag       bool
	scrapeOpts       scrape.Config
	scrapeConfigPath string
)

func scrapeScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scrape-scope <projectDir> <scopeConfig>",
		Short: "Crawl and scrape all in-scope targets",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScrapeScope(cmd, args, scrapeOpts)
		},
	}
	return cmd
}

func runScrapeScope(cmd *cobra.Command, args []string, opts scrape.Config) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: aegis --scrape-scope <projectDir> <scopeConfig>")
	}
	cfg := opts
	if scrapeConfigPath != "" {
		fileCfg, err := loadScrapeConfig(scrapeConfigPath)
		if err != nil {
			return err
		}
		cfg = fileCfg
		applyScrapeOverrides(cmd, opts, &cfg)
	}
	cfg.SessionKey = sessionKey
	return scrape.ScrapeScope(args[0], args[1], cfg)
}

func bindScrapeFlags(flags *pflag.FlagSet, opts *scrape.Config) {
	flags.IntVar(&opts.MaxDepth, "scrape-max-depth", 2, "Maximum crawl depth for scope scraping")
	flags.IntVar(&opts.WorkerCount, "scrape-workers", 2, "Concurrent crawl workers for scope scraping")
	flags.BoolVar(&opts.Headless, "scrape-headless", true, "Run browser in headless mode for scope scraping")
	flags.BoolVar(&opts.Scroll, "scrape-scroll", false, "Scroll to bottom to trigger lazy loading")
	flags.BoolVar(&opts.IncludeExternal, "scrape-include-external", false, "Include out-of-scope links/assets")
	flags.BoolVar(&opts.AllowPrivateHosts, "scrape-allow-private-hosts", false, "Allow localhost/private IP targets")
	flags.StringVar(&opts.UserAgent, "scrape-user-agent", "", "Custom User-Agent for scraping")
	flags.StringVar(&opts.OutputDir, "scrape-output-dir", "", "Output directory for scraped content")
	flags.StringToStringVar(&opts.Headers, "scrape-header", nil, "Extra HTTP headers (key=value)")
	flags.IntVar(&opts.MaxPages, "scrape-max-pages", 0, "Max pages to scrape (0 = unlimited)")
	flags.IntVar(&opts.MaxLinksPerPage, "scrape-max-links", 0, "Max links to enqueue per page (0 = unlimited)")
	flags.IntVar(&opts.RequestDelayMillis, "scrape-request-delay-ms", 0, "Delay between HTTP requests in milliseconds")
	flags.BoolVar(&opts.EnableScreenshot, "scrape-enable-screenshot", false, "Capture screenshots during scope scraping")
	flags.StringVar(&opts.ScreenshotPath, "scrape-screenshot-path", "", "Directory for screenshots during scope scraping")
	flags.StringVar(&opts.SessionPath, "scrape-session", "", "Path to session file (optional)")
	flags.StringVar(&opts.ManifestFormat, "scrape-format", "json", "Manifest format: json or yaml")
	flags.IntVar(&opts.PageTimeoutSeconds, "scrape-page-timeout", 30, "Page timeout in seconds")
	flags.IntVar(&opts.DownloadTimeoutSeconds, "scrape-download-timeout", 30, "Download timeout in seconds")
	flags.Int64Var(&opts.MaxDownloadBytes, "scrape-max-download-bytes", 20*1024*1024, "Max bytes per downloaded asset")
}

func loadScrapeConfig(path string) (scrape.Config, error) {
	configData, err := os.ReadFile(path)
	if err != nil {
		return scrape.Config{}, fmt.Errorf("failed to read scrape config file %s: %w", path, err)
	}

	var cfg scrape.Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return scrape.Config{}, fmt.Errorf("failed to parse scrape config file: %w", err)
	}
	return cfg, nil
}

func applyScrapeOverrides(cmd *cobra.Command, cli scrape.Config, cfg *scrape.Config) {
	if flagChanged(cmd, "scrape-max-depth") {
		cfg.MaxDepth = cli.MaxDepth
	}
	if flagChanged(cmd, "scrape-workers") {
		cfg.WorkerCount = cli.WorkerCount
	}
	if flagChanged(cmd, "scrape-headless") {
		cfg.Headless = cli.Headless
	}
	if flagChanged(cmd, "scrape-scroll") {
		cfg.Scroll = cli.Scroll
	}
	if flagChanged(cmd, "scrape-include-external") {
		cfg.IncludeExternal = cli.IncludeExternal
	}
	if flagChanged(cmd, "scrape-allow-private-hosts") {
		cfg.AllowPrivateHosts = cli.AllowPrivateHosts
	}
	if flagChanged(cmd, "scrape-user-agent") {
		cfg.UserAgent = cli.UserAgent
	}
	if flagChanged(cmd, "scrape-output-dir") {
		cfg.OutputDir = cli.OutputDir
	}
	if flagChanged(cmd, "scrape-header") {
		cfg.Headers = cli.Headers
	}
	if flagChanged(cmd, "scrape-max-pages") {
		cfg.MaxPages = cli.MaxPages
	}
	if flagChanged(cmd, "scrape-max-links") {
		cfg.MaxLinksPerPage = cli.MaxLinksPerPage
	}
	if flagChanged(cmd, "scrape-request-delay-ms") {
		cfg.RequestDelayMillis = cli.RequestDelayMillis
	}
	if flagChanged(cmd, "scrape-enable-screenshot") {
		cfg.EnableScreenshot = cli.EnableScreenshot
	}
	if flagChanged(cmd, "scrape-screenshot-path") {
		cfg.ScreenshotPath = cli.ScreenshotPath
	}
	if flagChanged(cmd, "scrape-session") {
		cfg.SessionPath = cli.SessionPath
	}
	if flagChanged(cmd, "scrape-format") {
		cfg.ManifestFormat = cli.ManifestFormat
	}
	if flagChanged(cmd, "scrape-page-timeout") {
		cfg.PageTimeoutSeconds = cli.PageTimeoutSeconds
	}
	if flagChanged(cmd, "scrape-download-timeout") {
		cfg.DownloadTimeoutSeconds = cli.DownloadTimeoutSeconds
	}
	if flagChanged(cmd, "scrape-max-download-bytes") {
		cfg.MaxDownloadBytes = cli.MaxDownloadBytes
	}
}

func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Changed(name) {
		return true
	}
	if cmd.PersistentFlags().Changed(name) {
		return true
	}
	return cmd.InheritedFlags().Changed(name)
}

func apiCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Start the REST API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := api.NewServer()
			return srv.Start(addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "Address to listen on")
	return cmd
}

func benchCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Run performance benchmarks",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			// Simple benchmark logic
			fmt.Printf("Benchmarking target: %s\n", target)
			// Implementation...
			duration := time.Since(start)
			fmt.Printf("Completed in %v\n", duration)
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Target URL for benchmarking")
	return cmd
}

func authCmd() *cobra.Command {
	var sessionPath, targetURL string

	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Capture and persist the authenticated browser session.",
		RunE: func(cmd *cobra.Command, args []string) error {
			browser := rod.New().MustConnect()
			defer browser.MustClose()

			if targetURL == "" {
				return fmt.Errorf("--target-url is required for authentication")
			}

			page := browser.MustPage(targetURL)
			fmt.Printf("Navigated to %s. Please authenticate in the browser.\n", targetURL)
			fmt.Println("After authenticating, press Enter to save the session...")
			fmt.Scanln()

			mgr := session.NewSessionManager(sessionPath, sessionKey)
			if err := mgr.Save(page); err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			log.Info("Session saved", "path", mgr.Path())
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionPath, "session", "session_lock.json", "file where the session lock is stored")
	cmd.Flags().StringVar(&targetURL, "target-url", "", "URL to authenticate against (required)")
	return cmd
}

func crawlCmd() *cobra.Command {
	var cfgPath, dumpPath, sessionPath string
	var includeExternal bool
	var renderVerify string
	var renderBorderLow int
	var renderBorderHigh int
	var renderTextDeltaMin int
	var renderMaxBytes int64

	cmd := &cobra.Command{
		Use:   "crawl",
		Short: "Run the discovery spider against the target application",
		RunE: func(cmd *cobra.Command, args []string) error {
			configData, err := os.ReadFile(cfgPath)
			if err != nil {
				return fmt.Errorf("failed to read config file %s: %w", cfgPath, err)
			}

			var config crawler.Config
			if err := yaml.Unmarshal(configData, &config); err != nil {
				return fmt.Errorf("failed to parse config file: %w", err)
			}
			if cmd.Flags().Changed("include-external") {
				config.IncludeExternal = includeExternal
			}
			if cmd.Flags().Changed("render-verify") {
				config.RenderVerify = renderVerify
			}
			if cmd.Flags().Changed("render-border-low") {
				config.RenderBorderLow = renderBorderLow
			}
			if cmd.Flags().Changed("render-border-high") {
				config.RenderBorderHigh = renderBorderHigh
			}
			if cmd.Flags().Changed("render-text-delta-min") {
				config.RenderTextDeltaMin = renderTextDeltaMin
			}
			if cmd.Flags().Changed("render-max-bytes") {
				config.RenderMaxBytes = renderMaxBytes
			}
			if len(sessionKey) > 0 {
				config.SessionKey = sessionKey
			}

			c := crawler.NewCrawler(config, sessionPath)
			if err := c.Run(dumpPath); err != nil {
				return fmt.Errorf("crawler failed: %w", err)
			}

			log.Info("Crawling completed", "dump", dumpPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "configs/config.yaml", "crawler configuration file")
	cmd.Flags().StringVar(&dumpPath, "dump", "crawl", "local mirror directory")
	cmd.Flags().StringVar(&sessionPath, "session", "session_lock.json", "file where the session lock is stored")
	cmd.Flags().BoolVar(&includeExternal, "include-external", false, "Allow crawling external domains")
	cmd.Flags().StringVar(&renderVerify, "render-verify", "auto", "Render verification mode: auto, never, always")
	cmd.Flags().IntVar(&renderBorderLow, "render-border-low", 3, "Rendercheck borderline low score")
	cmd.Flags().IntVar(&renderBorderHigh, "render-border-high", 8, "Rendercheck borderline high score")
	cmd.Flags().IntVar(&renderTextDeltaMin, "render-text-delta-min", 350, "Rendercheck visible text delta threshold")
	cmd.Flags().Int64Var(&renderMaxBytes, "render-max-bytes", 2<<20, "Rendercheck/static HTML max bytes")
	return cmd
}

func scanCmd() *cobra.Command {
	var inputPath, outputFormat, outputFile string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Analyze the mirrored dump for secret or dangerous artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := scanner.NewScanner(inputPath)
			findings, err := s.Scan()
			if err != nil {
				return fmt.Errorf("scanner failed: %w", err)
			}

			if len(findings) == 0 {
				log.Info("No security issues found")
				return nil
			}

			switch outputFormat {
			case "console":
				printFindingsConsole(findings)
			case "json":
				outputFindingsJSON(findings, outputFile)
			case "html":
				outputFindingsHTML(findings, outputFile)
			default:
				return fmt.Errorf("unsupported format: %s", outputFormat)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&inputPath, "input", "crawl", "path to the mirrored dump")
	cmd.Flags().StringVar(&outputFormat, "format", "console", "output format (console, json, html)")
	cmd.Flags().StringVar(&outputFile, "output", "", "output file")
	return cmd
}

func reconCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Perform Web2 and Web3 reconnaissance",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("target is required")
			}

			w2 := recon.NewWeb2Manager()
			subdomains, _ := w2.DiscoverSubdomains(target)
			fmt.Printf("Web2 Subdomains: %v\n", subdomains)

			w3 := recon.NewWeb3Manager()
			// In a real scenario, we'd pull content from a crawl or direct fetch
			artifacts := w3.AnalyzeContent("Contact us at 0x71C7656EC7ab88b098defB751B7401B5f6d8976F or aegis.eth")
			fmt.Printf("Web3 Addresses: %v\n", artifacts.Addresses)
			fmt.Printf("Web3 ENS Names: %v\n", artifacts.ENSNames)

			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Target domain or address")
	return cmd
}

func intelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Gather and process threat intelligence feeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := intel.NewIntelManager()
			log.Info("Gathering threat intelligence...")
			return manager.FetchUpdates()
		},
	}
	return cmd
}

func printFindingsConsole(findings []scanner.Finding) {
	for _, f := range findings {
		fmt.Printf("[%s] %s in %s:%d\n  Summary: %s\n", f.Severity, f.Type, f.File, f.Line, f.Summary)
	}
}

func outputFindingsJSON(findings []scanner.Finding, outputFile string) error {
	data, _ := json.MarshalIndent(findings, "", "  ")
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func outputFindingsHTML(findings []scanner.Finding, outputFile string) error {
	const tpl = `<html><body><h1>Findings</h1><ul>{{range .}}<li>[{{.Severity}}] {{.Type}} in {{.File}}</li>{{end}}</ul></body></html>`
	t, _ := template.New("report").Parse(tpl)
	if outputFile != "" {
		f, _ := os.Create(outputFile)
		defer f.Close()
		return t.Execute(f, findings)
	}
	return t.Execute(os.Stdout, findings)
}
