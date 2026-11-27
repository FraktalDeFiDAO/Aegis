// aegis-native-host is launched by the browser, not by a shell wrapper.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/coppertone/bug-hunter/app/aegis/internal/nativehost"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// stdout is reserved exclusively for native messaging frames.
	if err := nativehost.Run(ctx, os.Stdin, os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
