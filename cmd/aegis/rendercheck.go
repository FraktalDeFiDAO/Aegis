package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/rendercheck"
	"github.com/spf13/cobra"
)

func rendercheckCmd() *cobra.Command {
	var (
		rawURL    string
		timeout   time.Duration
		maxBytes  int64
		verify    string
		headless  bool
		insecure  bool
		userAgent string
		borderLow int
		borderHi  int
		deltaMin  int
	)

	cmd := &cobra.Command{
		Use:   "rendercheck",
		Short: "Decide if a page needs JS rendering",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(rawURL) == "" {
				return fmt.Errorf("--url is required")
			}

			mode := rendercheck.VerifyMode(verify)
			switch mode {
			case rendercheck.VerifyAuto, rendercheck.VerifyNever, rendercheck.VerifyAlways:
			default:
				return fmt.Errorf("invalid --verify: %s", verify)
			}

			opts := rendercheck.Options{
				Timeout:      timeout,
				MaxBytes:     maxBytes,
				UserAgent:    userAgent,
				InsecureTLS:  insecure,
				Verify:       mode,
				Headless:     headless,
				BorderLow:    borderLow,
				BorderHigh:   borderHi,
				TextDeltaMin: deltaMin,
			}

			ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
			defer cancel()

			res, err := rendercheck.NeedsRendering(ctx, rawURL, opts)
			if err != nil && res == nil {
				return err
			}
			if err != nil {
				if res.Errors == nil {
					res.Errors = map[string]string{}
				}
				res.Errors["fatal"] = err.Error()
			}

			if encodeErr := rendercheck.EncodeResult(os.Stdout, res); encodeErr != nil {
				return encodeErr
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&rawURL, "url", "", "URL to analyze")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "overall timeout (fetch + optional render)")
	cmd.Flags().Int64Var(&maxBytes, "max-bytes", 2<<20, "max bytes to read from initial HTML")
	cmd.Flags().StringVar(&verify, "verify", string(rendercheck.VerifyAuto), "verify mode: auto|never|always")
	cmd.Flags().BoolVar(&headless, "headless", true, "run browser headless (rod)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification (not recommended)")
	cmd.Flags().StringVar(&userAgent, "ua", "Mozilla/5.0 (compatible; RenderCheck/1.0; +https://example.invalid)", "User-Agent for initial fetch")
	cmd.Flags().IntVar(&borderLow, "border-low", 3, "borderline low score (inclusive)")
	cmd.Flags().IntVar(&borderHi, "border-high", 8, "borderline high score (exclusive)")
	cmd.Flags().IntVar(&deltaMin, "text-delta-min", 350, "visible text delta to mark rendering needed")

	return cmd
}
