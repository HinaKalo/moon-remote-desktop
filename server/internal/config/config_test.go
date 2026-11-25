package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var prodFiles = map[string]string{
	"MRD_DSN_FILE":        "/etc/mrd/dsn",
	"MRD_MASTER_KEY_FILE": "/etc/mrd/master.key",
	"MRD_ROSTER_KEY_FILE": "/etc/mrd/roster.key",
	"MRD_SSO_CLIENT_IDS":  "ms_desktop, ms_web",
}

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(prodFiles))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8621" || c.SSOIssuer != "https://sso.moonl.cloud" || c.Dev || len(c.SSOClientIDs) != 2 || c.SSOClientIDs[1] != "ms_web" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	want := "https://release.moonl.cloud/v1/apps/moon-remote/windows-x64-setup/latest/download"
	if got := c.WindowsDownloadURL(); got != want {
		t.Fatalf("download URL = %q, want %q", got, want)
	}
}

func TestProductionNeedsSecrets(t *testing.T) {
	_, err := Load(env(nil))
	if err == nil || !strings.Contains(err.Error(), "MRD_DSN_FILE, MRD_MASTER_KEY_FILE, MRD_ROSTER_KEY_FILE, MRD_SSO_CLIENT_IDS") {
		t.Fatalf("missing secrets not reported: %v", err)
	}
}

func TestOverridesAndLists(t *testing.T) {
	c, err := Load(env(with(prodFiles, "MRD_PUBLIC_URL", "http://127.0.0.1:8631/", "MRD_LISTEN", " :9000 ",
		"MRD_TURN_SECRET_FILE", "/s", "MRD_TURN_URLS", "turns:t:443?transport=tcp")))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "http://127.0.0.1:8631" || c.Listen != ":9000" {
		t.Fatalf("overrides not applied: %+v", c)
	}
}

func TestRejectsRelativeURL(t *testing.T) {
	if _, err := Load(env(with(prodFiles, "MRD_SSO_ISSUER", "sso.moonl.cloud"))); err == nil {
		t.Fatal("expected error for URL without scheme")
	}
}

func TestDevModeOnlyOnLoopback(t *testing.T) {
	dev := map[string]string{"MRD_DEV": "1", "MRD_PUBLIC_URL": "http://127.0.0.1:8621"}
	if c, err := Load(env(dev)); err != nil || !c.Dev {
		t.Fatalf("loopback dev mode refused: %v", err)
	}
	if _, err := Load(env(with(dev, "MRD_PUBLIC_URL", "https://remote.moonl.cloud"))); err == nil {
		t.Fatal("dev mode with public URL accepted")
	}
	if _, err := Load(env(with(dev, "MRD_LISTEN", "0.0.0.0:8621"))); err == nil {
		t.Fatal("dev mode on all interfaces accepted")
	}
}

func TestETSettings(t *testing.T) {
	et := with(prodFiles, "MRD_ET_CORE", "/opt/et/easytier-core", "MRD_ET_CLI", "/opt/et/easytier-cli",
		"MRD_ET_DATA_DIR", "/var/lib/mrd/et", "MRD_ET_PUBLIC_HOST", "remote.moonl.cloud", "MRD_ET_PORTS", "21000-21999")
	c, err := Load(env(et))
	if err != nil || !c.ETEnabled() || c.ETPortMin != 21000 || c.ETPortMax != 21999 {
		t.Fatalf("et config: %+v %v", c, err)
	}
	if c, _ := Load(env(prodFiles)); c.ETEnabled() {
		t.Fatal("EasyTier must be off when not configured")
	}
	if _, err := Load(env(with(et, "MRD_ET_CLI", ""))); err == nil {
		t.Fatal("partial EasyTier settings accepted")
	}
	for _, bad := range []string{"21000", "22000-21000", "80-90", "21000-70000", "a-b"} {
		if _, err := Load(env(with(et, "MRD_ET_PORTS", bad))); err == nil {
			t.Errorf("port range %q accepted", bad)
		}
	}
}

func TestTURNSettingsTogether(t *testing.T) {
	if _, err := Load(env(with(prodFiles, "MRD_TURN_URLS", "turn:x"))); err == nil {
		t.Fatal("TURN URLs without secret accepted")
	}
}

func TestReadSecretFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	_ = os.WriteFile(p, []byte("  value\n"), 0o600)
	if s, err := ReadSecretFile(p); err != nil || s != "value" {
		t.Fatalf("%q %v", s, err)
	}
	_ = os.WriteFile(p, []byte("\n"), 0o600)
	if _, err := ReadSecretFile(p); err == nil {
		t.Fatal("empty secret accepted")
	}
}
