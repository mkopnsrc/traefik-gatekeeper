// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 mkopnsrc

// traefik-gatekeeper lets visitors ask for access to traefik-protected sites;
// an approver decides with Telegram buttons, and approved addresses are added
// to a traefik ipAllowList for a limited time.
//
//	traefik-gatekeeper              serve (settings from GK_* variables)
//	traefik-gatekeeper healthcheck  exit 0 if the local server answers /healthz
//	traefik-gatekeeper version      print the version
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mkopnsrc/traefik-gatekeeper/internal/config"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/state"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/telegram"
	"github.com/mkopnsrc/traefik-gatekeeper/internal/web"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "healthcheck":
		err = healthcheck()
	case len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version"):
		fmt.Println(version)
	case len(os.Args) > 1:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	default:
		err = serve()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "traefik-gatekeeper:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := state.Open(state.Options{
		AllowlistDir: cfg.AllowlistDir, AllowlistFile: cfg.AllowlistFile, StateDir: cfg.StateDir,
		Middleware: cfg.MiddlewareName, Depth: cfg.IPStrategyDepth, Base: cfg.BaseRanges,
		Durations: cfg.Durations, PendingTTL: cfg.PendingTTL,
		MaxActive: cfg.MaxActive, PerIPHour: cfg.PerIPHour, GlobalHour: cfg.GlobalHour,
		InPlace: cfg.AllowlistInPlace,
	})
	if err != nil {
		return err
	}
	tg, err := telegram.New(cfg.TelegramAPI, cfg.TelegramTokenFile, cfg.TelegramChatID, cfg.TelegramApprovers)
	if err != nil {
		return err
	}
	srv, err := web.New(cfg, st, tg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go tg.Poll(ctx,
		func(d telegram.Decision) { srv.Decide(ctx, d) },
		srv.Rejected,
		func(err error) { slog.Warn("telegram poll", "err", err) })
	go srv.Sweep(ctx, 30*time.Second)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "version", version, "addr", cfg.Listen, "base_path", cfg.BasePath,
			"allowlist", cfg.AllowlistFile, "middleware", cfg.MiddlewareName)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shut)
}

func healthcheck() error {
	addr := os.Getenv("GK_LISTEN")
	if addr == "" {
		addr = ":5000"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	return nil
}
