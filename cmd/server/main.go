package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/twolate0101/hw_demo/internal/api"
	"github.com/twolate0101/hw_demo/internal/fingerprint"
)

func main() {
	addr := flag.String("addr", envOr("FINGERPRINT_ADDR", ":8080"), "HTTP listen address")
	rulesPath := flag.String("rules", envOr("FINGERPRINT_RULES", "rules/fingerprints.json"), "fingerprint rules file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	engine, err := fingerprint.NewEngine(*rulesPath)
	if err != nil {
		logger.Error("load fingerprint engine", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              *addr,
		Handler:           api.NewHandler(engine, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("fingerprint server listening", "address", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			_ = server.Close()
			os.Exit(1)
		}
		logger.Info("fingerprint server stopped")
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("fingerprint server failed", "error", err)
			os.Exit(1)
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
