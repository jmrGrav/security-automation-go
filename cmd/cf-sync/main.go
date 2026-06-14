package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jm/security-automation-go/internal/buildmeta"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML config file")
	mode := flag.String("mode", "cli", "Execution mode (cli|daemon|doctor|status|ui)")
	dryRun := flag.Bool("dry-run", true, "Execute in dry-run mode (default true)")
	format := flag.String("format", "text", "Output format (text|json)")
	metricsAddr := flag.String("metrics-addr", "127.0.0.1:9092", "Address to expose Prometheus metrics and API")
	versionFlag := flag.Bool("version", false, "Print build metadata and exit")
	flag.Parse()

	if *versionFlag {
		printVersion(os.Stdout)
		return
	}

	runCFSync(*configPath, *mode, *dryRun, *format, *metricsAddr, flag.Args())
}

func versionText() string {
	return buildmeta.Current().String()
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintln(w, versionText())
}
