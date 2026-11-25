// Package config reads moon-remote-server settings from the environment.
//
// Secrets are never passed as values: each is read from a file named by a *_FILE
// variable, so they do not appear in process listings or unit files.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds process-wide settings.
type Config struct {
	// Listen is the address the HTTP server binds; Caddy terminates TLS in front of it.
	Listen string
	// PublicURL is the externally visible origin, e.g. https://remote.moonl.cloud.
	PublicURL string
	// SSOIssuer is the OpenID issuer whose access tokens are accepted.
	SSOIssuer string
	// SSOClientIDs are the OAuth clients (desktop app, web client) whose access tokens
	// are accepted. Required outside dev mode.
	SSOClientIDs []string
	// ReleaseURL is the release-publish base URL used for download links.
	ReleaseURL string
	// ReleaseApp is the relhub app id.
	ReleaseApp string

	// Dev enables local development mode: "Authorization: Dev <sub>" sign-in from
	// loopback, in-memory store when no DSN is given, and throwaway keys when key files
	// are not given. Only allowed when Listen and PublicURL are loopback.
	Dev bool

	// DSNFile holds the MySQL DSN. Required outside dev mode.
	DSNFile string
	// MasterKeyFile holds base64 of 32 bytes sealing EasyTier network secrets.
	MasterKeyFile string
	// RosterKeyFile holds base64 of a 32-byte Ed25519 seed signing LAN rosters.
	RosterKeyFile string

	// TURNSecretFile holds coturn's static-auth-secret. TURN is off when empty.
	TURNSecretFile string
	TURNURLs       []string
	STUNURLs       []string

	// EasyTier server nodes (all or none): easytier-core / easytier-cli binaries,
	// a private data directory, the host devices dial and the listener port range
	// ("21000-21999", one port per account network).
	ETCorePath   string
	ETCLIPath    string
	ETDataDir    string
	ETPublicHost string
	ETPortMin    int
	ETPortMax    int

	// AllowedOrigins are extra browser origins (host patterns) for the signalling
	// WebSocket besides same-origin.
	AllowedOrigins []string
}

const (
	defaultListen     = "127.0.0.1:8621"
	defaultPublicURL  = "https://remote.moonl.cloud"
	defaultSSOIssuer  = "https://sso.moonl.cloud"
	defaultReleaseURL = "https://release.moonl.cloud"
	defaultReleaseApp = "moon-remote"
)

// FromEnv reads MRD_* variables, falling back to production defaults.
func FromEnv() (Config, error) {
	return Load(os.Getenv)
}

// Load is FromEnv with an injectable lookup, for tests.
func Load(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	list := func(key string) []string {
		var out []string
		for _, s := range strings.Split(getenv(key), ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	c := Config{
		Listen:         get("MRD_LISTEN", defaultListen),
		PublicURL:      strings.TrimRight(get("MRD_PUBLIC_URL", defaultPublicURL), "/"),
		SSOIssuer:      strings.TrimRight(get("MRD_SSO_ISSUER", defaultSSOIssuer), "/"),
		SSOClientIDs:   list("MRD_SSO_CLIENT_IDS"),
		ReleaseURL:     strings.TrimRight(get("MRD_RELEASE_URL", defaultReleaseURL), "/"),
		ReleaseApp:     get("MRD_RELEASE_APP", defaultReleaseApp),
		Dev:            get("MRD_DEV", "") == "1",
		DSNFile:        get("MRD_DSN_FILE", ""),
		MasterKeyFile:  get("MRD_MASTER_KEY_FILE", ""),
		RosterKeyFile:  get("MRD_ROSTER_KEY_FILE", ""),
		TURNSecretFile: get("MRD_TURN_SECRET_FILE", ""),
		TURNURLs:       list("MRD_TURN_URLS"),
		STUNURLs:       list("MRD_STUN_URLS"),
		ETCorePath:     get("MRD_ET_CORE", ""),
		ETCLIPath:      get("MRD_ET_CLI", ""),
		ETDataDir:      get("MRD_ET_DATA_DIR", ""),
		ETPublicHost:   get("MRD_ET_PUBLIC_HOST", ""),
		AllowedOrigins: list("MRD_ALLOWED_ORIGINS"),
	}
	for name, raw := range map[string]string{
		"MRD_PUBLIC_URL":  c.PublicURL,
		"MRD_SSO_ISSUER":  c.SSOIssuer,
		"MRD_RELEASE_URL": c.ReleaseURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return Config{}, fmt.Errorf("%s must be an absolute http(s) URL, got %q", name, raw)
		}
	}
	if c.Dev {
		if !loopbackHostPort(c.Listen) || !loopbackURL(c.PublicURL) {
			return Config{}, errors.New("MRD_DEV=1 requires a loopback MRD_LISTEN and MRD_PUBLIC_URL")
		}
	} else {
		var missing []string
		for name, v := range map[string]string{"MRD_DSN_FILE": c.DSNFile, "MRD_MASTER_KEY_FILE": c.MasterKeyFile, "MRD_ROSTER_KEY_FILE": c.RosterKeyFile} {
			if v == "" {
				missing = append(missing, name)
			}
		}
		if len(c.SSOClientIDs) == 0 {
			missing = append(missing, "MRD_SSO_CLIENT_IDS")
		}
		if len(missing) > 0 {
			return Config{}, fmt.Errorf("missing required settings: %s", strings.Join(sorted(missing), ", "))
		}
	}
	if err := c.loadETPorts(get("MRD_ET_PORTS", "")); err != nil {
		return Config{}, err
	}
	if (c.TURNSecretFile == "") != (len(c.TURNURLs) == 0) {
		return Config{}, errors.New("MRD_TURN_SECRET_FILE and MRD_TURN_URLS must be set together")
	}
	return c, nil
}

// ETEnabled reports whether EasyTier server nodes are configured.
func (c Config) ETEnabled() bool { return c.ETCorePath != "" }

func (c *Config) loadETPorts(ports string) error {
	set := 0
	for _, v := range []string{c.ETCorePath, c.ETCLIPath, c.ETDataDir, c.ETPublicHost, ports} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return nil
	}
	if set != 5 {
		return errors.New("MRD_ET_CORE, MRD_ET_CLI, MRD_ET_DATA_DIR, MRD_ET_PUBLIC_HOST and MRD_ET_PORTS must be set together")
	}
	lo, hi, ok := strings.Cut(ports, "-")
	portMin, err1 := strconv.Atoi(strings.TrimSpace(lo))
	portMax, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || portMin < 1024 || portMax > 65535 || portMin > portMax {
		return fmt.Errorf("MRD_ET_PORTS must look like 21000-21999, got %q", ports)
	}
	c.ETPortMin, c.ETPortMax = portMin, portMax
	return nil
}

// WindowsDownloadURL is the "latest installer" link shown on the web client.
func (c Config) WindowsDownloadURL() string {
	return c.ReleaseURL + "/v1/apps/" + url.PathEscape(c.ReleaseApp) + "/windows-x64-setup/latest/download"
}

// ReadSecretFile returns the trimmed contents of a secret file.
func ReadSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

func loopbackHostPort(hp string) bool {
	host, _, err := net.SplitHostPort(hp)
	return err == nil && isLoopbackHost(host)
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isLoopbackHost(u.Hostname())
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func sorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
