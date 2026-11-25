package et

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/store"
)

type fakeIssuer struct {
	mu      sync.Mutex
	issued  []string
	revoked []string
	specs   []NetworkSpec
}

func (f *fakeIssuer) Issue(_ context.Context, n NetworkSpec, id string, ttl time.Duration) (Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, id)
	f.specs = append(f.specs, n)
	return Credential{Secret: "cred-" + id, ExpiresAt: time.Unix(2_000_000_000, 0).Add(ttl)}, nil
}

func (f *fakeIssuer) Revoke(_ context.Context, n NetworkSpec, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, id)
	return nil
}

func TestSealer(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.Seal([]byte("top secret"), "alice")
	if bytes.Contains(sealed, []byte("top secret")) {
		t.Fatal("plaintext visible")
	}
	got, err := s.Open(sealed, "alice")
	if err != nil || string(got) != "top secret" {
		t.Fatalf("open: %v %q", err, got)
	}
	if _, err := s.Open(sealed, "bob"); err == nil {
		t.Fatal("secret moved to another user must not open")
	}
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestChooseSubnet(t *testing.T) {
	for range 50 {
		p, err := ChooseSubnet(nil)
		if err != nil || p.Bits() != 24 || !Pool.Contains(p.Addr()) {
			t.Fatalf("subnet %v %v", p, err)
		}
		third := p.Addr().As4()[2]
		if third == 0 || third == 255 {
			t.Fatalf("edge subnet chosen: %v", p)
		}
	}
	// Everything but 10.250.42.0/24 is taken.
	var occ []netip.Prefix
	for i := 1; i <= 254; i++ {
		if i != 42 {
			occ = append(occ, netip.MustParsePrefix(netip.AddrFrom4([4]byte{10, 250, byte(i), 0}).String()+"/24"))
		}
	}
	if p, _ := ChooseSubnet(occ); p.String() != "10.250.42.0/24" {
		t.Fatalf("only free subnet not chosen: %v", p)
	}
	if _, err := ChooseSubnet([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); !errors.Is(err, ErrNoFreeSubnet) {
		t.Fatalf("covering prefix: %v", err)
	}
}

func TestHostAddressAndParse(t *testing.T) {
	if got := HostAddress(netip.MustParsePrefix("10.250.17.0/24"), 3).String(); got != "10.250.17.3/24" {
		t.Fatal(got)
	}
	ps, err := ParseOccupied([]string{"192.168.1.20/24", "fd00::/8", "10.126.126.0/24"})
	if err != nil || len(ps) != 2 || ps[0].String() != "192.168.1.0/24" {
		t.Fatalf("parse: %v %v", ps, err)
	}
	if _, err := ParseOccupied([]string{"nonsense"}); err == nil {
		t.Fatal("bad prefix accepted")
	}
}

type env struct {
	svc    *Service
	store  *store.Memory
	issuer *fakeIssuer
	srv    *httptest.Server
}

func newEnv(t *testing.T, withIssuer bool) *env {
	t.Helper()
	st := store.NewMemory()
	sealer, _ := NewSealer(bytes.Repeat([]byte{9}, 32))
	e := &env{store: st, issuer: &fakeIssuer{}}
	e.svc = &Service{
		Store: st, Sealer: sealer, PublicHost: "et.example", PortMin: 21000, PortMax: 21999,
		Auth: &auth.Authenticator{Users: auth.Unconfigured{}, Store: st}, Log: slog.New(slog.DiscardHandler),
	}
	if withIssuer {
		e.svc.Issuer = e.issuer
	}
	mux := http.NewServeMux()
	e.svc.Register(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) device(t *testing.T, sub string) (store.Device, string) {
	t.Helper()
	now := time.Now()
	_ = e.store.UpsertUser(context.Background(), store.User{Sub: sub, DisplayName: sub, CreatedAt: now, UpdatedAt: now})
	tok, hash := auth.NewDeviceToken()
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	d := store.Device{ID: auth.NewID(), UserSub: sub, Name: "PC", Kind: store.KindHost, PublicKey: pub, TokenHash: hash, CreatedAt: now, LastSeenAt: now}
	if err := e.store.CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d, tok
}

func (e *env) post(t *testing.T, token string, occupied []string) (int, Grant, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"occupied": occupied})
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/et/credential", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Device "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var raw map[string]any
	_ = json.NewDecoder(res.Body).Decode(&raw)
	var g Grant
	rb, _ := json.Marshal(raw)
	_ = json.Unmarshal(rb, &g)
	code, _ := raw["error"].(string)
	return res.StatusCode, g, code
}

func TestGrantFlow(t *testing.T) {
	e := newEnv(t, true)
	a, ta := e.device(t, "alice")
	b, tb := e.device(t, "alice")

	code, ga, _ := e.post(t, ta, []string{"192.168.1.0/24"})
	if code != 200 || ga.Credential != "cred-"+a.ID || ga.NetworkName == "" || len(ga.Peers) != 2 ||
		!strings.HasPrefix(ga.Peers[0], "tcp://et.example:21") || ga.Peers[1] != "udp"+strings.TrimPrefix(ga.Peers[0], "tcp") {
		t.Fatalf("grant a: %d %+v", code, ga)
	}
	_, gb, _ := e.post(t, tb, nil)
	if gb.NetworkName != ga.NetworkName {
		t.Fatal("devices of one account must share a network")
	}
	pa, pb := netip.MustParsePrefix(ga.IPv4), netip.MustParsePrefix(gb.IPv4)
	if pa.Addr() == pb.Addr() || pa.Masked() != pb.Masked() || pa.Addr().As4()[3] != 2 || pb.Addr().As4()[3] != 3 {
		t.Fatalf("addresses: %v %v", pa, pb)
	}
	// The secret given to the node is the stored one and never appears in the grant.
	spec := e.issuer.specs[0]
	if spec.Secret == "" || spec.Secret == ga.Credential || e.issuer.specs[1].Secret != spec.Secret {
		t.Fatal("network secret handling")
	}

	// Another account gets a different network.
	_, tc := e.device(t, "bob")
	_, gc, _ := e.post(t, tc, nil)
	if gc.NetworkName == ga.NetworkName || gc.Peers[0] == ga.Peers[0] {
		t.Fatal("accounts must have their own network and node port")
	}

	// Revocation reaches the issuer.
	if err := e.svc.RevokeDevice(context.Background(), b); err != nil || len(e.issuer.revoked) != 1 {
		t.Fatalf("revoke: %v %v", err, e.issuer.revoked)
	}
}

func TestSubnetConflictOnLaterDevice(t *testing.T) {
	e := newEnv(t, true)
	_, ta := e.device(t, "alice")
	_, ga, _ := e.post(t, ta, nil)
	_, tb := e.device(t, "alice")
	code, _, errCode := e.post(t, tb, []string{netip.MustParsePrefix(ga.IPv4).Masked().String()})
	if code != http.StatusConflict || errCode != "subnet_conflict" {
		t.Fatalf("conflict: %d %s", code, errCode)
	}
}

func TestNotConfigured(t *testing.T) {
	e := newEnv(t, false)
	d, tok := e.device(t, "alice")
	if code, _, errCode := e.post(t, tok, nil); code != 503 || errCode != "et_unavailable" {
		t.Fatalf("not configured: %d %s", code, errCode)
	}
	if err := e.svc.RevokeDevice(context.Background(), d); err != nil {
		t.Fatalf("revoke without issuer must be a no-op: %v", err)
	}
}

func TestConcurrentFirstGrantSharesNetwork(t *testing.T) {
	e := newEnv(t, true)
	const n = 6
	toks := make([]string, n)
	for i := range toks {
		_, toks[i] = e.device(t, "alice")
	}
	names := make([]string, n)
	var wg sync.WaitGroup
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, g, _ := e.post(t, toks[i], nil)
			names[i] = g.NetworkName
		}()
	}
	wg.Wait()
	for _, nm := range names {
		if nm == "" || nm != names[0] {
			t.Fatalf("racing first grants created different networks: %v", names)
		}
	}
}
