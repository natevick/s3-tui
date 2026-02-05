package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/natevick/s3-tui/internal/security"
	"github.com/natevick/s3-tui/internal/tui"
)

var (
	version = "dev"
)

func main() {
	// Parse flags
	profile := flag.String("profile", os.Getenv("AWS_PROFILE"), "AWS profile to use (can also use AWS_PROFILE env var)")
	region := flag.String("region", os.Getenv("AWS_REGION"), "AWS region (can also use AWS_REGION env var)")
	bucket := flag.String("bucket", "", "Start directly in this S3 bucket")
	demo := flag.Bool("demo", false, "Run with mock data (no AWS credentials needed)")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("s3-tui version %s\n", version)
		os.Exit(0)
	}

	// Validate inputs
	if err := security.ValidProfileName(*profile); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid profile: %v\n", err)
		os.Exit(1)
	}
	if err := security.ValidBucketName(*bucket); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid bucket: %v\n", err)
		os.Exit(1)
	}

	// Create TUI model
	cfg := tui.Config{
		Profile:  *profile,
		Region:   *region,
		Bucket:   *bucket,
		DemoMode: *demo,
	}

	model := tui.New(cfg)

	// Create and run program
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running program: %v\n", err)
		os.Exit(1)
	}
}
