package main

import (
	"flag"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML config file")
	mode := flag.String("mode", "cli", "Execution mode (cli|daemon|doctor|status|ui)")
	dryRun := flag.Bool("dry-run", true, "Execute in dry-run mode (default true)")
	format := flag.String("format", "text", "Output format (text|json)")
	metricsAddr := flag.String("metrics-addr", "127.0.0.1:9092", "Address to expose Prometheus metrics and API")
	flag.Parse()

	runCFSync(*configPath, *mode, *dryRun, *format, *metricsAddr, flag.Args())
}
