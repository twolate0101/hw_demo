package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	apiClient "github.com/twolate0101/hw_demo/internal/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}

func run() error {
	defaultServer := os.Getenv("FINGERPRINT_SERVER_URL")
	if defaultServer == "" {
		defaultServer = "http://localhost:8080"
	}
	filePath := flag.String("file", "", "path to a JSON array of scan inputs")
	serverURL := flag.String("server", defaultServer, "fingerprint server base URL")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()
	if *filePath == "" {
		return fmt.Errorf("-file is required")
	}
	file, err := os.Open(*filePath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer file.Close()
	inputs, err := apiClient.DecodeInputs(file)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := apiClient.New(*serverURL, &http.Client{Timeout: *timeout})
	results, err := c.Fingerprint(ctx, inputs)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	return nil
}
