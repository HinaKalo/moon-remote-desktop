package roster

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s := NewSigner(priv)
	now := time.Unix(1_800_000_000, 0)
	sr, err := s.Sign("u1", []Entry{{ID: "d1", Name: "PC", Kind: "host", PublicKey: "AAAA"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Verify(s.PublicKey(), sr, now.Add(13*24*time.Hour))
	if err != nil || r.UserSub != "u1" || len(r.Devices) != 1 || sr.KeyID != s.KeyID() {
		t.Fatalf("verify: %v %+v", err, r)
	}
	if _, err := Verify(s.PublicKey(), sr, now.Add(Validity)); err == nil {
		t.Fatal("expired roster accepted")
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(other.Public().(ed25519.PublicKey), sr, now); err == nil {
		t.Fatal("wrong key accepted")
	}
	body, _ := base64.StdEncoding.DecodeString(sr.Roster)
	tampered := sr
	tampered.Roster = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(body), `"u1"`, `"u2"`, 1)))
	if _, err := Verify(s.PublicKey(), tampered, now); err == nil {
		t.Fatal("tampered roster accepted")
	}
}

func TestEmptyRosterEncodesArray(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	sr, _ := NewSigner(priv).Sign("u1", nil, time.Now())
	body, _ := base64.StdEncoding.DecodeString(sr.Roster)
	if !strings.Contains(string(body), `"devices":[]`) {
		t.Fatalf("devices must be [] not null: %s", body)
	}
}

func TestLoadSigner(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600)
	s, err := LoadSigner(good)
	if err != nil || !s.PublicKey().Equal(ed25519.NewKeyFromSeed(seed).Public()) {
		t.Fatalf("load: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("not base64!"), 0o600)
	if _, err := LoadSigner(bad); err == nil {
		t.Fatal("bad key accepted")
	}
}
