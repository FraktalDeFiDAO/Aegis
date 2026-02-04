package browser

import (
	"os"

	"github.com/go-rod/rod/lib/launcher"
)

// NewLauncher returns a launcher configured for the current runtime.
// Chromium requires --no-sandbox when running as root (common in containers).
func NewLauncher(headless bool) *launcher.Launcher {
	l := launcher.New().
		Headless(headless).
		Set("disable-gpu").
		Set("disable-dev-shm-usage").
		Set("disable-setuid-sandbox").
		Set("no-first-run").
		Set("no-sandbox").
		Set("no-zygote")

	if os.Geteuid() == 0 {
		l = l.NoSandbox(true)
	}
	return l
}
