package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"moon-remote/server/internal/config"
	"moon-remote/server/internal/devices"
	"moon-remote/server/internal/store"
)

// TestEasyTierThroughAPI drives the assembled server with real EasyTier nodes:
// register a device, get a grant, remove the device. Set MRD_TEST_ET_DIR as for
// TestNodeManagerWithRealEasyTier.
func TestEasyTierThroughAPI(t *testing.T) {
	dir := os.Getenv("MRD_TEST_ET_DIR")
	if dir == "" {
		t.Skip("MRD_TEST_ET_DIR not set")
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	dataDir := t.TempDir()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"MRD_DEV": "1", "MRD_PUBLIC_URL": "http://127.0.0.1:8621",
			"MRD_ET_CORE": filepath.Join(dir, "easytier-core"+exe), "MRD_ET_CLI": filepath.Join(dir, "easytier-cli"+exe),
			"MRD_ET_DATA_DIR": dataDir, "MRD_ET_PUBLIC_HOST": "127.0.0.1",
			// A one-port range makes the allocated port predictable for the test.
			"MRD_ET_PORTS": strconv.Itoa(port) + "-" + strconv.Itoa(port),
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	h, closer, err := Build(context.Background(), cfg, "test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()

	do := func(method, path, authz string, body any) (int, map[string]any) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", authz)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	_, ch := do("POST", "/v1/devices/challenge", "Dev alice", nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	nonce := ch["nonce"].(string)
	sig := ed25519.Sign(priv, devices.RegistrationMessage(nonce, "dev|alice", store.KindHost, pubB64))
	_, reg := do("POST", "/v1/devices", "Dev alice", map[string]string{
		"name": "Host", "kind": "host", "publicKey": pubB64, "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(sig),
	})
	devAuth := "Device " + reg["deviceToken"].(string)
	devID := reg["device"].(map[string]any)["id"].(string)

	code, grant := do("POST", "/v1/et/credential", devAuth, map[string]any{"occupied": []string{"192.168.1.0/24"}})
	if code != 200 {
		t.Fatalf("grant: %d %v", code, grant)
	}
	peers := grant["peers"].([]any)
	if grant["credential"] == "" || !strings.HasSuffix(grant["ipv4"].(string), ".2/24") ||
		peers[0] != "tcp://127.0.0.1:"+strconv.Itoa(port) || peers[1] != "udp://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("grant content: %v", grant)
	}
	// The network secret is in the server's data dir only in sealed form or the
	// node's environment; the device never sees it.
	if b, _ := json.Marshal(grant); strings.Contains(strings.ToLower(string(b)), "secret") {
		t.Fatalf("grant mentions a secret: %s", b)
	}

	// Removing the device revokes its credentials on the node.
	if code, out := do("DELETE", "/v1/devices/"+devID, "Dev alice", nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	store, _ := filepath.Glob(filepath.Join(dataDir, "*", "credentials.json"))
	if len(store) != 1 {
		t.Fatalf("credential store files: %v", store)
	}
	b, _ := os.ReadFile(store[0])
	if strings.Contains(string(b), devID+".") {
		t.Fatalf("device credential still in the admin store after delete: %s", b)
	}
}
