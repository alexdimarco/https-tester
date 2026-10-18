// Command httpsdiag launches the HTTPS Diagnostic Workbench: a local,
// capability-protected web interface backed by the Go probe engine. It opens a
// loopback server, prints (and best-effort opens) the URL, and runs until the
// operator shuts it down from the page or interrupts the process.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/alexdimarco/https-tester/internal/app"
	"github.com/alexdimarco/https-tester/internal/localapi"
)

// build is overridable at link time with -ldflags "-X main.build=...".
var build = "0.1.0-gate-a-dev"

func main() {
	noOpen := flag.Bool("no-open", false, "do not try to open a browser; just print the URL")
	maxLifetime := flag.Duration("max-lifetime", 30*time.Minute, "shut down automatically after this long as a safety bound")
	flag.Parse()

	buildInfo := fmt.Sprintf("%s (%s)", build, runtime.Version())
	session := app.NewSession(buildInfo)

	server, err := localapi.New(session)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	url := server.BootstrapURL()
	fmt.Println("HTTPS Diagnostic Workbench is running locally.")
	fmt.Println()
	fmt.Println("  Open this URL in your browser (it carries a single-use launch token):")
	fmt.Println("   ", url)
	fmt.Println()
	fmt.Println("  Results stay on this machine. Press Ctrl-C or use \"Shut down\" in the page to stop.")

	if !*noOpen {
		tryOpen(url)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-server.ShutdownRequested():
		fmt.Println("\nShutdown requested from the page.")
	case <-sigCh:
		fmt.Println("\nInterrupted.")
	case <-time.After(*maxLifetime):
		fmt.Println("\nReached the maximum lifetime bound; shutting down.")
	case err := <-serveErr:
		if err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "shutdown error:", err)
	}
	fmt.Println("Stopped.")
}

// tryOpen makes a best effort to open the default browser. Failure is silent:
// the URL is already printed, and some environments intentionally block this.
func tryOpen(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
