// Package storetest is the behavioural contract every store.Store must pass.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"moon-remote/server/internal/store"
)

// Run executes the contract against stores built by newStore. Each subtest gets a
// fresh store; implementations backed by a shared database must isolate by using the
// unique subjects this suite generates.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("users", func(t *testing.T) { testUsers(t, newStore(t)) })
	t.Run("devices", func(t *testing.T) { testDevices(t, newStore(t)) })
	t.Run("isolation", func(t *testing.T) { testIsolation(t, newStore(t)) })
	t.Run("et_hosts", func(t *testing.T) { testETHosts(t, newStore(t)) })
	t.Run("et_hosts_concurrent", func(t *testing.T) { testETHostsConcurrent(t, newStore(t)) })
	t.Run("networks", func(t *testing.T) { testNetworks(t, newStore(t)) })
}

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func newUser(t *testing.T, s store.Store) string {
	t.Helper()
	sub := "test|" + randHex(8)
	if err := s.UpsertUser(context.Background(), store.User{Sub: sub, DisplayName: "Test", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return sub
}

func newDevice(sub string) store.Device {
	tok := sha256.Sum256(randBytes(32))
	return store.Device{
		ID: randHex(16), UserSub: sub, Name: "PC", Kind: store.KindHost,
		PublicKey: randBytes(32), TokenHash: tok[:], CreatedAt: now, LastSeenAt: now,
	}
}

func mustCreate(t *testing.T, s store.Store, d store.Device) {
	t.Helper()
	if err := s.CreateDevice(context.Background(), d); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
}

func testUsers(t *testing.T, s store.Store) {
	ctx := context.Background()
	sub := newUser(t, s)
	later := now.Add(time.Hour)
	if err := s.UpsertUser(ctx, store.User{Sub: sub, DisplayName: "Renamed", CreatedAt: later, UpdatedAt: later}); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if u.DisplayName != "Renamed" || !u.CreatedAt.Equal(now) || !u.UpdatedAt.Equal(later) {
		t.Fatalf("upsert must keep created_at and update the rest: %+v", u)
	}
	if _, err := s.GetUser(ctx, "nobody|"+randHex(4)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
}

func testDevices(t *testing.T, s store.Store) {
	ctx := context.Background()
	sub := newUser(t, s)
	d := newDevice(sub)
	mustCreate(t, s, d)

	got, err := s.GetDevice(ctx, sub, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "PC" || got.Kind != store.KindHost || !bytes.Equal(got.PublicKey, d.PublicKey) || got.ETHost != 0 {
		t.Fatalf("round trip: %+v", got)
	}
	byTok, err := s.DeviceByTokenHash(ctx, d.TokenHash)
	if err != nil || byTok.ID != d.ID {
		t.Fatalf("by token: %v %+v", err, byTok)
	}

	dup := newDevice(sub)
	dup.PublicKey = d.PublicKey
	if err := s.CreateDevice(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key twice for one user: %v", err)
	}
	if err := s.CreateDevice(ctx, newDevice("ghost|"+randHex(4))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device for unknown user: %v", err)
	}

	second := newDevice(sub)
	second.CreatedAt = now.Add(time.Minute)
	mustCreate(t, s, second)
	list, err := s.ListDevices(ctx, sub)
	if err != nil || len(list) != 2 || list[0].ID != d.ID || list[1].ID != second.ID {
		t.Fatalf("list order: %v %+v", err, list)
	}

	if err := s.RenameDevice(ctx, sub, d.ID, "Office"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameDevice(ctx, sub, d.ID, "Office"); err != nil {
		t.Fatalf("rename to same name must succeed: %v", err)
	}
	seen := now.Add(2 * time.Hour)
	if err := s.TouchDevice(ctx, d.ID, seen); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetDevice(ctx, sub, d.ID)
	if got.Name != "Office" || !got.LastSeenAt.Equal(seen) {
		t.Fatalf("rename/touch: %+v", got)
	}

	if err := s.DeleteDevice(ctx, sub, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, sub, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := s.DeviceByTokenHash(ctx, d.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("token of deleted device still resolves: %v", err)
	}
	if err := s.TouchDevice(ctx, d.ID, seen); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("touch deleted: %v", err)
	}
}

func testIsolation(t *testing.T, s store.Store) {
	ctx := context.Background()
	alice, bob := newUser(t, s), newUser(t, s)
	d := newDevice(alice)
	mustCreate(t, s, d)

	if _, err := s.GetDevice(ctx, bob, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob reads alice's device: %v", err)
	}
	if err := s.RenameDevice(ctx, bob, d.ID, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob renames alice's device: %v", err)
	}
	if err := s.DeleteDevice(ctx, bob, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob deletes alice's device: %v", err)
	}
	if _, err := s.AssignETHost(ctx, bob, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob assigns alice's address: %v", err)
	}
	if list, _ := s.ListDevices(ctx, bob); len(list) != 0 {
		t.Fatalf("bob lists alice's devices: %+v", list)
	}
	// The same public key may be registered by two different users.
	other := newDevice(bob)
	other.PublicKey = d.PublicKey
	mustCreate(t, s, other)
}

func testETHosts(t *testing.T, s store.Store) {
	ctx := context.Background()
	sub := newUser(t, s)
	a, b := newDevice(sub), newDevice(sub)
	mustCreate(t, s, a)
	mustCreate(t, s, b)

	ha, err := s.AssignETHost(ctx, sub, a.ID)
	if err != nil || ha != store.FirstETHost {
		t.Fatalf("first host: %d %v", ha, err)
	}
	if again, _ := s.AssignETHost(ctx, sub, a.ID); again != ha {
		t.Fatalf("assignment must be stable: %d != %d", again, ha)
	}
	hb, err := s.AssignETHost(ctx, sub, b.ID)
	if err != nil || hb != store.FirstETHost+1 {
		t.Fatalf("second host: %d %v", hb, err)
	}
	// Freed numbers are reused.
	if err := s.DeleteDevice(ctx, sub, a.ID); err != nil {
		t.Fatal(err)
	}
	c := newDevice(sub)
	mustCreate(t, s, c)
	if hc, _ := s.AssignETHost(ctx, sub, c.ID); hc != store.FirstETHost {
		t.Fatalf("freed number not reused: %d", hc)
	}
	// Another user's numbering is independent.
	other := newUser(t, s)
	od := newDevice(other)
	mustCreate(t, s, od)
	if ho, _ := s.AssignETHost(ctx, other, od.ID); ho != store.FirstETHost {
		t.Fatalf("per-user numbering: %d", ho)
	}
}

func testETHostsConcurrent(t *testing.T, s store.Store) {
	ctx := context.Background()
	sub := newUser(t, s)
	const n = 8
	ids := make([]string, n)
	for i := range ids {
		d := newDevice(sub)
		mustCreate(t, s, d)
		ids[i] = d.ID
	}
	var wg sync.WaitGroup
	hosts := make([]int, n)
	errs := make([]error, n)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hosts[i], errs[i] = s.AssignETHost(ctx, sub, ids[i])
		}()
	}
	wg.Wait()
	seen := map[int]bool{}
	for i, h := range hosts {
		if errs[i] != nil {
			t.Fatalf("assign %d: %v", i, errs[i])
		}
		if seen[h] {
			t.Fatalf("host %d handed out twice: %v", h, hosts)
		}
		seen[h] = true
	}
}

func testNetworks(t *testing.T, s store.Store) {
	ctx := context.Background()
	sub := newUser(t, s)
	if _, err := s.GetNetwork(ctx, sub); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no network yet: %v", err)
	}
	port := 20000 + int(randBytes(2)[0])*40 + int(randBytes(1)[0]%40) // random so a shared DB does not collide
	n := store.Network{UserSub: sub, NetworkName: "mrd-" + randHex(8), SecretSealed: randBytes(60), CIDR: "10.250.17.0/24", ListenPort: port, CreatedAt: now}
	if err := s.CreateNetwork(ctx, n); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNetwork(ctx, sub)
	if err != nil || got.NetworkName != n.NetworkName || got.CIDR != n.CIDR || got.ListenPort != port || !bytes.Equal(got.SecretSealed, n.SecretSealed) {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	if err := s.CreateNetwork(ctx, n); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second network for user: %v", err)
	}
	other := newUser(t, s)
	clash := n
	clash.UserSub = other
	clash.ListenPort = 0
	if err := s.CreateNetwork(ctx, clash); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate network name: %v", err)
	}
	samePort := store.Network{UserSub: other, NetworkName: "mrd-" + randHex(8), SecretSealed: randBytes(60), CIDR: "10.250.18.0/24", ListenPort: port, CreatedAt: now}
	if err := s.CreateNetwork(ctx, samePort); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate listen port: %v", err)
	}
	list, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range list {
		if x.NetworkName == n.NetworkName && x.ListenPort == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListNetworks misses %s", n.NetworkName)
	}
}
