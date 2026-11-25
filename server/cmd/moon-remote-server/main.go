// Command moon-remote-server is the control plane behind remote.moonl.cloud: device
// registry, signalling, EasyTier credential issuance, TURN credentials and the web
// viewer.
//
// Usage:
//
//	moon-remote-server [serve]   run the HTTP server (default)
//	moon-remote-server migrate   apply database migrations and exit
//	moon-remote-server keygen    print a new base64 32-byte key (master key or roster seed)
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"moon-remote/server/internal/app"
	"moon-remote/server/internal/config"
)

// version is stamped at build time: -ldflags "-X main.version=0.1.0+123".
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "migrate":
		err = migrate(log)
	case "keygen":
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		fmt.Println(base64.StdEncoding.EncodeToString(key))
	default:
		err = fmt.Errorf("unknown command %q (want serve, migrate or keygen)", cmd)
	}
	if err != nil {
		log.Error("exit", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func migrate(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if cfg.DSNFile == "" {
		return errors.New("MRD_DSN_FILE is required for migrate")
	}
	ctx := context.Background()
	d, err := app.OpenDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Migrate(ctx, log)
}

func serve(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler, closer, err := app.Build(ctx, cfg, version, log)
	if err != nil {
		return err
	}
	defer closer.Close()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "version", version, "dev", cfg.Dev)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Shutdown does not wait for hijacked WebSocket connections; clients reconnect.
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
