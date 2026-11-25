// Package devices serves device registration, listing, renaming and removal, and the
// signed roster used by LAN direct mode.
package devices

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/httpx"
	"moon-remote/server/internal/roster"
	"moon-remote/server/internal/store"
)

// Presence reports live signalling connections; implemented by the signal hub.
type Presence interface {
	Online(deviceID string) bool
	// Disconnect closes every signalling connection of the device.
	Disconnect(deviceID string)
}

// Revoker withdraws a removed device's network access; implemented by the EasyTier
// service. A nil Revoker is allowed while EasyTier is not configured.
type Revoker interface {
	RevokeDevice(ctx context.Context, d store.Device) error
}

// API holds the dependencies of the device routes.
type API struct {
	Store      store.Store
	Auth       *auth.Authenticator
	Challenges *auth.Challenges
	Roster     *roster.Signer
	Presence   Presence
	Revoker    Revoker
	Log        *slog.Logger
	Now        func() time.Time
}

// MaxDevicesPerUser bounds registrations per account; it equals the number of
// EasyTier host addresses available in the account's /24.
const MaxDevicesPerUser = store.LastETHost - store.FirstETHost + 1

// MaxNameRunes is the longest accepted device name.
const MaxNameRunes = 64

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Register adds the routes to mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/devices/challenge", a.Auth.Require(auth.AllowUser, http.HandlerFunc(a.challenge)))
	mux.Handle("POST /v1/devices", a.Auth.Require(auth.AllowUser, http.HandlerFunc(a.create)))
	mux.Handle("GET /v1/devices", a.Auth.Require(auth.AllowAny, http.HandlerFunc(a.list)))
	mux.Handle("PATCH /v1/devices/{id}", a.Auth.Require(auth.AllowUser, http.HandlerFunc(a.rename)))
	mux.Handle("DELETE /v1/devices/{id}", a.Auth.Require(auth.AllowAny, http.HandlerFunc(a.remove)))
	mux.Handle("GET /v1/roster", a.Auth.Require(auth.AllowDevice, http.HandlerFunc(a.roster)))
}

// View is the JSON shape of a device.
type View struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	PublicKey  string    `json:"publicKey"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Online     bool      `json:"online"`
	// Self is true for the device making the request (device-token callers only).
	Self bool `json:"self,omitempty"`
}

func (a *API) view(d store.Device, caller auth.Principal) View {
	return View{
		ID: d.ID, Name: d.Name, Kind: string(d.Kind),
		PublicKey: base64.StdEncoding.EncodeToString(d.PublicKey),
		CreatedAt: d.CreatedAt.UTC(), LastSeenAt: d.LastSeenAt.UTC(),
		Online: a.Presence != nil && a.Presence.Online(d.ID),
		Self:   caller.DeviceID == d.ID,
	}
}

// RegistrationMessage is the exact byte string a device signs with its Ed25519 key to
// register. Binding the user and kind stops a captured signature from being replayed
// into another account or with another role; the nonce makes it single-use.
func RegistrationMessage(nonce, userSub string, kind store.DeviceKind, publicKeyB64 string) []byte {
	return []byte("moonrd/device-register/v1\n" + nonce + "\n" + userSub + "\n" + string(kind) + "\n" + publicKeyB64)
}

func (a *API) challenge(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	nonce, exp, err := a.Challenges.Issue(p.UserSub)
	if err != nil {
		httpx.WriteError(w, http.StatusTooManyRequests, "too_many_challenges", "try again shortly")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nonce": nonce, "expiresAt": exp.UTC()})
}

type createRequest struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PublicKey string `json:"publicKey"` // base64 (std), 32 bytes
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // base64 (std) over RegistrationMessage
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req createRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "name must be 1-64 printable characters")
		return
	}
	kind := store.DeviceKind(req.Kind)
	if !kind.Valid() {
		httpx.WriteError(w, http.StatusBadRequest, "bad_kind", `kind must be "host" or "viewer"`)
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		httpx.WriteError(w, http.StatusBadRequest, "bad_public_key", "publicKey must be base64 of a 32-byte Ed25519 key")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	// Consume the nonce before checking the signature so a nonce never survives a failed attempt.
	if !a.Challenges.Consume(p.UserSub, req.Nonce) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_nonce", "challenge unknown, expired or already used")
		return
	}
	if err != nil || !ed25519.Verify(pub, RegistrationMessage(req.Nonce, p.UserSub, kind, req.PublicKey), sig) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_signature", "signature does not verify")
		return
	}

	existing, err := a.Store.ListDevices(r.Context(), p.UserSub)
	if err != nil {
		a.internal(w, "list devices", err)
		return
	}
	if len(existing) >= MaxDevicesPerUser {
		httpx.WriteError(w, http.StatusConflict, "too_many_devices", "remove an old device first")
		return
	}

	now := a.now()
	token, hash := auth.NewDeviceToken()
	d := store.Device{
		ID: auth.NewID(), UserSub: p.UserSub, Name: name, Kind: kind,
		PublicKey: pub, TokenHash: hash, CreatedAt: now, LastSeenAt: now,
	}
	switch err := a.Store.CreateDevice(r.Context(), d); {
	case errors.Is(err, store.ErrConflict):
		httpx.WriteError(w, http.StatusConflict, "already_registered", "this device key is already registered")
		return
	case err != nil:
		a.internal(w, "create device", err)
		return
	}
	a.Log.Info("device registered", "user", p.UserSub, "device", d.ID, "kind", kind)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"device":      a.view(d, p),
		"deviceToken": token,
		// Clients pin this key to verify LAN rosters later.
		"rosterKey":   base64.StdEncoding.EncodeToString(a.Roster.PublicKey()),
		"rosterKeyId": a.Roster.KeyID(),
	})
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	if p.IsDevice() {
		_ = a.Store.TouchDevice(r.Context(), p.DeviceID, a.now())
	}
	ds, err := a.Store.ListDevices(r.Context(), p.UserSub)
	if err != nil {
		a.internal(w, "list devices", err)
		return
	}
	out := make([]View, 0, len(ds))
	for _, d := range ds {
		out = append(out, a.view(d, p))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (a *API) rename(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Name string `json:"name"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "name must be 1-64 printable characters")
		return
	}
	switch err := a.Store.RenameDevice(r.Context(), p.UserSub, r.PathValue("id"), name); {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such device")
	case err != nil:
		a.internal(w, "rename device", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id := r.PathValue("id")
	// A device may unregister itself, but not its siblings.
	if p.IsDevice() && p.DeviceID != id {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "a device can only remove itself")
		return
	}
	d, err := a.Store.GetDevice(r.Context(), p.UserSub, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.internal(w, "get device", err)
		return
	}
	// Revoke network access first: if that fails the device stays listed and the
	// user can retry, instead of a deleted device keeping a working credential.
	if a.Revoker != nil {
		if err := a.Revoker.RevokeDevice(r.Context(), d); err != nil {
			a.Log.Error("revoke device network access", "device", id, "err", err)
			httpx.WriteError(w, http.StatusBadGateway, "revoke_failed", "could not revoke network access; try again")
			return
		}
	}
	if err := a.Store.DeleteDevice(r.Context(), p.UserSub, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.internal(w, "delete device", err)
		return
	}
	if a.Presence != nil {
		a.Presence.Disconnect(id)
	}
	a.Log.Info("device removed", "user", p.UserSub, "device", id, "by_device", p.IsDevice())
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) roster(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	ds, err := a.Store.ListDevices(r.Context(), p.UserSub)
	if err != nil {
		a.internal(w, "list devices", err)
		return
	}
	entries := make([]roster.Entry, 0, len(ds))
	for _, d := range ds {
		entries = append(entries, roster.Entry{
			ID: d.ID, Name: d.Name, Kind: string(d.Kind), PublicKey: base64.StdEncoding.EncodeToString(d.PublicKey),
		})
	}
	signed, err := a.Roster.Sign(p.UserSub, entries, a.now())
	if err != nil {
		a.internal(w, "sign roster", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, signed)
}

func (a *API) internal(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

// cleanName trims and validates a user-supplied device name.
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxNameRunes {
		return "", false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return s, true
}
