// Package app assembles moon-remote-server from its configuration.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/config"
	"moon-remote/server/internal/db"
	"moon-remote/server/internal/devices"
	"moon-remote/server/internal/et"
	"moon-remote/server/internal/httpapi"
	"moon-remote/server/internal/roster"
	"moon-remote/server/internal/rsauth"
	"moon-remote/server/internal/signal"
	"moon-remote/server/internal/store"
	"moon-remote/server/internal/store/mysqlstore"
	"moon-remote/server/internal/support"
	"moon-remote/server/internal/turn"
	"moon-remote/server/internal/web"
)

// OpenDB connects to MySQL using the DSN file from cfg.
func OpenDB(ctx context.Context, cfg config.Config) (*db.DB, error) {
	dsn, err := config.ReadSecretFile(cfg.DSNFile)
	if err != nil {
		return nil, fmt.Errorf("read DSN: %w", err)
	}
	return db.Open(ctx, db.Options{DSN: dsn, MaxOpenConns: 20, MaxIdleConns: 5, ConnMaxLifetime: 30 * time.Minute})
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type closers []func() error

func (c closers) Close() error {
	var errs []error
	for i := len(c) - 1; i >= 0; i-- {
		errs = append(errs, c[i]())
	}
	return errors.Join(errs...)
}

// Build returns the root handler and a closer for its resources.
func Build(ctx context.Context, cfg config.Config, version string, log *slog.Logger) (http.Handler, io.Closer, error) {
	var (
		st     store.Store
		closer io.Closer = nopCloser{}
	)
	switch {
	case cfg.DSNFile != "":
		d, err := OpenDB(ctx, cfg)
		if err != nil {
			return nil, nil, err
		}
		if err := d.CheckSchema(ctx); err != nil {
			d.Close()
			return nil, nil, err
		}
		st, closer = mysqlstore.New(d), d
	case cfg.Dev:
		log.Warn("dev mode: in-memory store, data is lost on restart")
		st = store.NewMemory()
	default:
		return nil, nil, errors.New("no database configured")
	}

	fail := func(err error) (http.Handler, io.Closer, error) {
		return nil, nil, errors.Join(err, closer.Close())
	}
	sealer, err := loadSealer(cfg, log)
	if err != nil {
		return fail(err)
	}
	signer, err := loadRosterSigner(cfg, log)
	if err != nil {
		return fail(err)
	}

	users, err := userVerifier(cfg, log)
	if err != nil {
		return fail(err)
	}
	authn := &auth.Authenticator{Users: users, Store: st, Log: log}

	hub := &signal.Hub{Auth: authn, Store: st, Log: log, OriginPatterns: cfg.AllowedOrigins}

	etSvc := &et.Service{
		Store: st, Sealer: sealer, PublicHost: cfg.ETPublicHost, PortMin: cfg.ETPortMin, PortMax: cfg.ETPortMax,
		Auth: authn, Log: log,
	}
	if cfg.ETEnabled() {
		nodes := &et.NodeManager{CorePath: cfg.ETCorePath, CLIPath: cfg.ETCLIPath, DataDir: cfg.ETDataDir, Log: log}
		etSvc.Issuer = nodes
		prev := closer
		closer = closers{prev.Close, func() error { nodes.Close(); return nil }}
		// Bring existing networks back up so devices with valid credentials reconnect.
		go etSvc.StartAll(context.WithoutCancel(ctx))
	} else {
		log.Warn("EasyTier not configured: /v1/et/credential answers 503")
	}

	devAPI := &devices.API{
		Store: st, Auth: authn, Challenges: &auth.Challenges{TTL: 2 * time.Minute, Max: 10_000},
		Roster: signer, Presence: hub, Revoker: etSvc, Log: log,
	}

	var turnIssuer *turn.Issuer
	if cfg.TURNSecretFile != "" {
		secret, err := config.ReadSecretFile(cfg.TURNSecretFile)
		if err != nil {
			return fail(err)
		}
		turnIssuer = &turn.Issuer{Secret: []byte(secret), URLs: cfg.TURNURLs, STUN: cfg.STUNURLs}
	}

	supportAPI := &support.API{Auth: authn}
	webSPA := web.Handler{Dir: "web/dist"}

	h := httpapi.New(cfg, version, devAPI, etSvc, hub, supportAPI, webSPA, registrarFunc(func(mux *http.ServeMux) {
		turnIssuer.Register(mux, authn)
	}))
	return h, closer, nil
}

type registrarFunc func(*http.ServeMux)

func (f registrarFunc) Register(mux *http.ServeMux) { f(mux) }

// userVerifier builds sign-in verification: sso.moonl.cloud access tokens for the
// configured clients, plus the loopback-only Dev scheme in dev mode.
func userVerifier(cfg config.Config, log *slog.Logger) (auth.UserVerifier, error) {
	var ssoV auth.UserVerifier
	if len(cfg.SSOClientIDs) > 0 {
		sso, err := moonsso.NewClient(moonsso.Config{Issuer: cfg.SSOIssuer, ClientID: "moon-remote-server"})
		if err != nil {
			return nil, fmt.Errorf("sso client: %w", err)
		}
		v, err := rsauth.New(rsauth.Config{
			SSO: sso,
			// Moon SSO always puts the client id in aud and adds the resource when the
			// login passed one; the client allowlist is the real gate.
			Audiences:      append(append([]string{}, cfg.SSOClientIDs...), cfg.PublicURL),
			AllowedClients: cfg.SSOClientIDs,
			PublicURL:      cfg.PublicURL,
			// Moon SSO issues Bearer access tokens today; bound tokens are still checked.
			RequireDPoP: false,
		})
		if err != nil {
			return nil, err
		}
		ssoV = &auth.SSOVerifier{V: v, SSO: sso}
		log.Info("SSO verification enabled", "issuer", cfg.SSOIssuer, "clients", cfg.SSOClientIDs)
	}
	if !cfg.Dev {
		return ssoV, nil // config.Load guarantees client ids outside dev mode
	}
	log.Warn("dev mode: accepting 'Authorization: Dev <sub>' from loopback")
	return auth.ByScheme{Dev: auth.DevVerifier{}, Other: ssoV}, nil
}

func loadSealer(cfg config.Config, log *slog.Logger) (*et.Sealer, error) {
	if cfg.MasterKeyFile != "" {
		return et.LoadSealer(cfg.MasterKeyFile)
	}
	log.Warn("dev mode: throwaway master key")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return et.NewSealer(key)
}

func loadRosterSigner(cfg config.Config, log *slog.Logger) (*roster.Signer, error) {
	if cfg.RosterKeyFile != "" {
		return roster.LoadSigner(cfg.RosterKeyFile)
	}
	log.Warn("dev mode: throwaway roster key")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return roster.NewSigner(priv), nil
}
