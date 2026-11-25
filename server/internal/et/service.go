// Package et is the single source of EasyTier network access.
//
// Each account gets its own EasyTier network. Its secret is generated here, stored
// sealed, and only ever handed to the server-side EasyTier node (through an Issuer).
// Devices receive short-lived per-device credentials instead, so no client binary
// contains anything that grants network access, and removing a device revokes it.
package et

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/httpx"
	"moon-remote/server/internal/store"
)

// NetworkSpec is everything the server-side EasyTier node needs to serve a network.
type NetworkSpec struct {
	Name   string
	Secret string
	// Subnet is the account's /24; the server node takes host .1.
	Subnet netip.Prefix
	// ListenPort is the node's public TCP and UDP port.
	ListenPort int
}

// Credential is a per-device EasyTier credential.
type Credential struct {
	Secret    string
	ExpiresAt time.Time
}

// Issuer talks to the server-side EasyTier nodes; NodeManager is the implementation.
type Issuer interface {
	// Issue makes sure the node serves the network and returns a fresh credential
	// for deviceID valid for ttl.
	Issue(ctx context.Context, n NetworkSpec, deviceID string, ttl time.Duration) (Credential, error)
	// Revoke invalidates every credential issued to deviceID and disconnects it.
	Revoke(ctx context.Context, n NetworkSpec, deviceID string) error
}

// DefaultTTL is how long a device credential lasts; clients renew at 75%.
const DefaultTTL = 24 * time.Hour

// Service hands out network access.
type Service struct {
	Store  store.Store
	Sealer *Sealer
	// Issuer is nil until EasyTier is configured; requests then fail with 503.
	Issuer Issuer
	// PublicHost is the name devices dial, e.g. remote.moonl.cloud.
	PublicHost string
	// PortMin..PortMax is the range of public listener ports, one per network.
	PortMin, PortMax int
	TTL              time.Duration
	Auth             *auth.Authenticator
	Log              *slog.Logger
	Now              func() time.Time
}

// ErrSubnetConflict means the account's subnet overlaps a range on the requesting device.
var ErrSubnetConflict = errors.New("et: account subnet overlaps a local network on this device")

// ErrNotConfigured means no Issuer is set.
var ErrNotConfigured = errors.New("et: easytier not configured")

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTTL
}

// ErrNoFreePort means every listener port in the configured range is taken.
var ErrNoFreePort = errors.New("et: no free listener port")

// network returns the account's network, creating it on first use with a subnet that
// avoids occupied and a free listener port.
func (s *Service) network(ctx context.Context, userSub string, occupied []netip.Prefix) (NetworkSpec, error) {
	n, err := s.Store.GetNetwork(ctx, userSub)
	if errors.Is(err, store.ErrNotFound) {
		n, err = s.createNetwork(ctx, userSub, occupied)
	}
	if err != nil {
		return NetworkSpec{}, err
	}
	return s.spec(n)
}

func (s *Service) createNetwork(ctx context.Context, userSub string, occupied []netip.Prefix) (store.Network, error) {
	subnet, err := ChooseSubnet(occupied)
	if err != nil {
		return store.Network{}, err
	}
	secret := NewNetworkSecret()
	n := store.Network{
		UserSub: userSub, NetworkName: NewNetworkName(), CIDR: subnet.String(),
		SecretSealed: s.Sealer.Seal([]byte(secret), userSub), CreatedAt: s.now(),
	}
	// Random port with retry: a conflict is either another device of this account
	// winning the race (use its network) or a port collision (try another port).
	for range 20 {
		n.ListenPort, err = randomPort(s.PortMin, s.PortMax)
		if err != nil {
			return store.Network{}, err
		}
		err = s.Store.CreateNetwork(ctx, n)
		if !errors.Is(err, store.ErrConflict) {
			return n, err
		}
		if existing, gerr := s.Store.GetNetwork(ctx, userSub); gerr == nil {
			return existing, nil
		}
	}
	return store.Network{}, ErrNoFreePort
}

func (s *Service) spec(n store.Network) (NetworkSpec, error) {
	secret, err := s.Sealer.Open(n.SecretSealed, n.UserSub)
	if err != nil {
		return NetworkSpec{}, fmt.Errorf("open network secret: %w", err)
	}
	subnet, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return NetworkSpec{}, fmt.Errorf("stored subnet %q: %w", n.CIDR, err)
	}
	if n.ListenPort == 0 {
		return NetworkSpec{}, fmt.Errorf("network %s has no listener port", n.NetworkName)
	}
	return NetworkSpec{Name: n.NetworkName, Secret: string(secret), Subnet: subnet, ListenPort: n.ListenPort}, nil
}

func randomPort(lo, hi int) (int, error) {
	if lo <= 0 || hi < lo || hi > 65535 {
		return 0, fmt.Errorf("et: bad listener port range %d-%d", lo, hi)
	}
	i, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, err
	}
	return lo + int(i.Int64()), nil
}

// peers returns the addresses devices dial for a network's node.
func (s *Service) peers(port int) []string {
	hp := net.JoinHostPort(s.PublicHost, strconv.Itoa(port))
	return []string{"tcp://" + hp, "udp://" + hp}
}

// Starter is implemented by issuers that run a node per network.
type Starter interface {
	Ensure(ctx context.Context, n NetworkSpec) error
}

// StartAll brings up the node of every existing network, so devices that still hold
// a valid credential can reconnect after a server restart. Errors are logged.
func (s *Service) StartAll(ctx context.Context) {
	starter, ok := s.Issuer.(Starter)
	if !ok {
		return
	}
	nets, err := s.Store.ListNetworks(ctx)
	if err != nil {
		s.Log.Error("list networks", "err", err)
		return
	}
	for _, n := range nets {
		spec, err := s.spec(n)
		if err == nil {
			err = starter.Ensure(ctx, spec)
		}
		if err != nil {
			s.Log.Error("start network node", "network", n.NetworkName, "err", err)
		}
	}
}

// Grant is the JSON returned to a device.
type Grant struct {
	NetworkName string    `json:"networkName"`
	Credential  string    `json:"credential"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Peers       []string  `json:"peers"`
	// IPv4 is the device's own address with prefix length, e.g. "10.250.17.3/24".
	IPv4 string `json:"ipv4"`
}

// GrantFor issues network access for one device.
func (s *Service) GrantFor(ctx context.Context, userSub, deviceID string, occupied []netip.Prefix) (Grant, error) {
	if s.Issuer == nil {
		return Grant{}, ErrNotConfigured
	}
	spec, err := s.network(ctx, userSub, occupied)
	if err != nil {
		return Grant{}, err
	}
	if overlapsAny(spec.Subnet, occupied) {
		return Grant{}, ErrSubnetConflict
	}
	host, err := s.Store.AssignETHost(ctx, userSub, deviceID)
	if err != nil {
		return Grant{}, err
	}
	cred, err := s.Issuer.Issue(ctx, spec, deviceID, s.ttl())
	if err != nil {
		return Grant{}, fmt.Errorf("issue credential: %w", err)
	}
	return Grant{
		NetworkName: spec.Name, Credential: cred.Secret, ExpiresAt: cred.ExpiresAt.UTC(),
		Peers: s.peers(spec.ListenPort), IPv4: HostAddress(spec.Subnet, host).String(),
	}, nil
}

// RevokeDevice implements devices.Revoker.
func (s *Service) RevokeDevice(ctx context.Context, d store.Device) error {
	if s.Issuer == nil {
		return nil // nothing was ever issued
	}
	n, err := s.Store.GetNetwork(ctx, d.UserSub)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	spec, err := s.spec(n)
	if err != nil {
		return err
	}
	return s.Issuer.Revoke(ctx, spec, d.ID)
}

// Register adds POST /v1/et/credential (device token only).
func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/et/credential", s.Auth.Require(auth.AllowDevice, http.HandlerFunc(s.handleCredential)))
}

func (s *Service) handleCredential(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var req struct {
		Occupied []string `json:"occupied"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	occupied, err := ParseOccupied(req.Occupied)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_occupied", err.Error())
		return
	}
	g, err := s.GrantFor(r.Context(), p.UserSub, p.DeviceID, occupied)
	switch {
	case errors.Is(err, ErrNotConfigured):
		httpx.WriteError(w, http.StatusServiceUnavailable, "et_unavailable", "virtual network is not available")
	case errors.Is(err, ErrSubnetConflict):
		httpx.WriteError(w, http.StatusConflict, "subnet_conflict", err.Error())
	case errors.Is(err, store.ErrFull), errors.Is(err, ErrNoFreeSubnet), errors.Is(err, ErrNoFreePort):
		httpx.WriteError(w, http.StatusConflict, "no_address", err.Error())
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "device no longer registered")
	case err != nil:
		s.Log.Error("et credential", "device", p.DeviceID, "err", err)
		httpx.WriteError(w, http.StatusBadGateway, "et_error", "could not issue network credential")
	default:
		s.Log.Info("et credential issued", "device", p.DeviceID, "expires", g.ExpiresAt)
		httpx.WriteJSON(w, http.StatusOK, g)
	}
}
