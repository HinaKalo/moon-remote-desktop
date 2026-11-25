package et

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseGenerated(t *testing.T) {
	for _, body := range []string{
		`{"credential_id":"d.1","credential_secret":"c2VjcmV0","expiry_unix":"1795267640"}`, // v2.7.1
		`{"credential_id":"d.1","credential_secret":"c2VjcmV0","expiry_unix":1795267640}`,   // v2.6.4
	} {
		c, err := ParseGenerated([]byte(body))
		if err != nil || c.Secret != "c2VjcmV0" || c.ExpiresAt.Unix() != 1795267640 {
			t.Fatalf("%s: %+v %v", body, c, err)
		}
	}
	for _, bad := range []string{`{}`, `{"credential_secret":"x","expiry_unix":"soon"}`, `not json`} {
		if _, err := ParseGenerated([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseCredentialIDs(t *testing.T) {
	ids, err := ParseCredentialIDs([]byte(`{}`))
	if err != nil || len(ids) != 0 {
		t.Fatalf("empty list: %v %v", ids, err)
	}
	ids, err = ParseCredentialIDs([]byte(`{"credentials":[{"credential_id":"a.1","expiry_unix":"9"},{"credential_id":"b.2"}]}`))
	if err != nil || !slices.Equal(ids, []string{"a.1", "b.2"}) {
		t.Fatalf("%v %v", ids, err)
	}
}

func TestStaleCredentialIDs(t *testing.T) {
	ids := []string{"dev.100", "dev.300", "dev.200", "devX.50", "other.1", "dev.garbage", "dev"}
	if got := StaleCredentialIDs(ids, "dev", 2); !slices.Equal(got, []string{"dev.100"}) {
		t.Fatalf("keep 2: %v", got)
	}
	got := StaleCredentialIDs(ids, "dev", 0)
	slices.Sort(got)
	if !slices.Equal(got, []string{"dev.100", "dev.200", "dev.300"}) {
		t.Fatalf("revoke all: %v (must not touch devX or other devices)", got)
	}
}

func TestNodeArgs(t *testing.T) {
	spec := NetworkSpec{Name: "mrd-abc", Secret: "SECRET", Subnet: netip.MustParsePrefix("10.250.17.0/24"), ListenPort: 21017}
	args := strings.Join(NodeArgs(spec, 40001, "/var/lib/mrd/et/mrd-abc/credentials.json"), " ")
	for _, want := range []string{
		"--network-name mrd-abc", "--secure-mode", "--credential-file /var/lib/mrd/et/mrd-abc/credentials.json",
		"-i 10.250.17.1/24", "--no-tun", "--listeners tcp://0.0.0.0:21017 udp://0.0.0.0:21017",
		"--rpc-portal 127.0.0.1:40001", "--rpc-portal-whitelist 127.0.0.1/32", "--disable-upnp", "--private-mode true",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
	if strings.Contains(args, "SECRET") {
		t.Fatal("network secret must not be on the command line")
	}
}

// TestNodeManagerWithRealEasyTier issues a credential, joins a device with it, and
// revokes it, against real EasyTier binaries. Set MRD_TEST_ET_DIR to a folder with
// easytier-core and easytier-cli (v2.7.1), e.g. spikes/easytier/vendor/nopacket-v2.7.1.
func TestNodeManagerWithRealEasyTier(t *testing.T) {
	dir := os.Getenv("MRD_TEST_ET_DIR")
	if dir == "" {
		t.Skip("MRD_TEST_ET_DIR not set")
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	core, cli := filepath.Join(dir, "easytier-core"+exe), filepath.Join(dir, "easytier-cli"+exe)

	listen, err := freeLoopbackPort() // TCP free; UDP of the same number is very likely free too
	if err != nil {
		t.Fatal(err)
	}
	spec := NetworkSpec{Name: NewNetworkName(), Secret: NewNetworkSecret(), Subnet: netip.MustParsePrefix("10.250.77.0/24"), ListenPort: listen}
	m := &NodeManager{CorePath: core, CLIPath: cli, DataDir: t.TempDir(), Log: slog.New(slog.DiscardHandler)}
	t.Cleanup(m.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cred, err := m.Issue(ctx, spec, "dev1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cred.Secret == "" || time.Until(cred.ExpiresAt) < 50*time.Minute {
		t.Fatalf("credential: %+v", cred)
	}
	if b, _ := os.ReadFile(filepath.Join(m.DataDir, spec.Name, "credentials.json")); len(b) == 0 {
		t.Fatal("admin credential store not written")
	}

	// Join a device the way moonrd-et does: TOML with the credential, no secret.
	devDir := t.TempDir()
	toml := fmt.Sprintf(`instance_name = "moonrd"
hostname = "dev1"
ipv4 = "10.250.77.2/24"
listeners = []

[network_identity]
network_name = %q

[[peer]]
uri = "tcp://127.0.0.1:%d"

[secure_mode]
enabled = true
local_private_key = %q

[flags]
dev_name = "moonrd0"
no_tun = true
`, spec.Name, listen, cred.Secret)
	cfg := filepath.Join(devDir, "moonrd.toml")
	if err := os.WriteFile(cfg, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	devRPC, _ := freeLoopbackPort()
	// --bind-device false only because this test dials a 127.0.0.1 peer (REPORT.md §3).
	dev := exec.Command(core, "-c", cfg, "--rpc-portal", net.JoinHostPort("127.0.0.1", fmt.Sprint(devRPC)),
		"--rpc-portal-whitelist", "127.0.0.1/32", "--bind-device", "false", "--console-log-level", "warn")
	devLog, _ := os.Create(filepath.Join(devDir, "dev.log"))
	dev.Stdout, dev.Stderr = devLog, devLog
	if err := dev.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dev.Process.Kill(); _ = dev.Wait(); devLog.Close() })
	t.Cleanup(func() {
		if t.Failed() {
			for _, f := range []string{filepath.Join(devDir, "dev.log"), filepath.Join(m.DataDir, spec.Name, "node.log")} {
				b, _ := os.ReadFile(f)
				t.Logf("---- %s\n%s", filepath.Base(f), tail(string(b), 3000))
			}
			if out, err := m.cli(context.Background(), m.nodes[spec.Name].rpcPort, "peer", "list"); err == nil {
				t.Logf("server peer list: %s", out)
			}
		}
	})

	nd, err := m.node(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := func() bool {
		out, err := m.cli(ctx, nd.rpcPort, "credential", "peers")
		if err != nil {
			return false
		}
		var cp struct {
			Credentials []struct {
				ID    string `json:"credential_id"`
				Peers []struct {
					Hostname string `json:"hostname"`
				} `json:"peers"`
			} `json:"credentials"`
		}
		if json.Unmarshal(out, &cp) != nil {
			return false
		}
		for _, c := range cp.Credentials {
			for _, p := range c.Peers {
				if p.Hostname == "dev1" && strings.HasPrefix(c.ID, "dev1.") {
					return true
				}
			}
		}
		return false
	}
	waitFor(t, 30*time.Second, "device joins with its credential", joined)

	// A second issue keeps the first credential (overlap); a third prunes the oldest.
	time.Sleep(2 * time.Millisecond)
	if _, err := m.Issue(ctx, spec, "dev1", time.Hour); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := m.Issue(ctx, spec, "dev1", time.Hour); err != nil {
		t.Fatal(err)
	}
	out, _ := m.cli(ctx, nd.rpcPort, "credential", "list")
	ids, _ := ParseCredentialIDs(out)
	if n := len(StaleCredentialIDs(ids, "dev1", 0)); n != keepPerDevice {
		t.Fatalf("want %d live credentials for dev1, have %d: %v", keepPerDevice, n, ids)
	}
	waitFor(t, 15*time.Second, "pruning the first credential disconnects the device", func() bool { return !joined() })

	// Revoke removes everything of the device.
	if err := m.Revoke(ctx, spec, "dev1"); err != nil {
		t.Fatal(err)
	}
	out, _ = m.cli(ctx, nd.rpcPort, "credential", "list")
	ids, _ = ParseCredentialIDs(out)
	if left := StaleCredentialIDs(ids, "dev1", 0); len(left) != 0 {
		t.Fatalf("credentials left after revoke: %v", left)
	}

	// The network secret is never on the node's command line.
	if strings.Contains(strings.Join(nd.cmd.Args, " "), spec.Secret) {
		t.Fatal("secret on argv")
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}
