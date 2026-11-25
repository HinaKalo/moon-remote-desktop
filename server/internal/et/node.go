package et

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NodeManager runs one easytier-core per account network on the server and issues
// device credentials through easytier-cli (EasyTier v2.7.1; see
// spikes/easytier/REPORT.md §2 and §7).
//
// Each node holds the network secret (passed in the environment, never on argv),
// listens publicly on the network's own port, and is the admin node that signs device
// credentials. Its management RPC binds a loopback port: `easytier-cli node` on that
// port prints the network secret, so the server host must be trusted.
type NodeManager struct {
	CorePath string
	CLIPath  string
	// DataDir holds one directory per network with its credential store and log.
	// It contains device private keys: keep it 0700 and owned by the service user.
	DataDir string
	Log     *slog.Logger
	Now     func() time.Time

	mu     sync.Mutex
	nodes  map[string]*node
	closed bool
}

// DeviceGroup is the EasyTier group every device credential carries.
const DeviceGroup = "mrd-devices"

// keepPerDevice is how many credentials of one device stay valid: the newest and its
// predecessor, so a device can switch keys without dropping off the network.
const keepPerDevice = 2

type node struct {
	rpcPort int
	cmd     *exec.Cmd
	ready   chan struct{} // closed when the RPC answered, or startup failed
	exited  chan struct{} // closed when the process ended
	err     error         // startup error, set before ready closes
}

func (n *node) alive() bool {
	select {
	case <-n.exited:
		return false
	default:
		return true
	}
}

func (m *NodeManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Ensure starts the network's node if it is not running.
func (m *NodeManager) Ensure(ctx context.Context, n NetworkSpec) error {
	_, err := m.node(ctx, n)
	return err
}

func (m *NodeManager) node(ctx context.Context, n NetworkSpec) (*node, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("et: node manager closed")
	}
	if m.nodes == nil {
		m.nodes = map[string]*node{}
	}
	nd := m.nodes[n.Name]
	if nd == nil || !nd.alive() {
		var err error
		nd, err = m.start(n)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		m.nodes[n.Name] = nd
		go m.waitReady(nd)
	}
	m.mu.Unlock()

	select {
	case <-nd.ready:
		return nd, nd.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// NodeArgs is the easytier-core command line for a network's server node.
func NodeArgs(n NetworkSpec, rpcPort int, credentialFile string) []string {
	server := HostAddress(n.Subnet, 1).String()
	port := strconv.Itoa(n.ListenPort)
	return []string{
		"--instance-name", n.Name,
		"--network-name", n.Name,
		"--secure-mode",
		"--credential-file", credentialFile,
		"--hostname", "mrd-server",
		"-i", server,
		"--no-tun",
		"--listeners", "tcp://0.0.0.0:" + port, "udp://0.0.0.0:" + port,
		"--rpc-portal", net.JoinHostPort("127.0.0.1", strconv.Itoa(rpcPort)),
		"--rpc-portal-whitelist", "127.0.0.1/32",
		"--disable-upnp",
		"--private-mode", "true",
		"--console-log-level", "warn",
	}
}

func (m *NodeManager) start(n NetworkSpec) (*node, error) {
	dir := filepath.Join(m.DataDir, n.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	rpc, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	logf, err := os.OpenFile(filepath.Join(dir, "node.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(m.CorePath, NodeArgs(n, rpc, filepath.Join(dir, "credentials.json"))...)
	cmd.Env = append(os.Environ(), "ET_NETWORK_SECRET="+n.Secret)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, fmt.Errorf("start easytier-core: %w", err)
	}
	nd := &node{rpcPort: rpc, cmd: cmd, ready: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		logf.Close()
		close(nd.exited)
		m.mu.Lock()
		closing := m.closed
		m.mu.Unlock()
		if !closing && m.Log != nil {
			m.Log.Warn("easytier node exited", "network", n.Name, "err", err)
		}
	}()
	if m.Log != nil {
		m.Log.Info("easytier node started", "network", n.Name, "port", n.ListenPort, "pid", cmd.Process.Pid)
	}
	return nd, nil
}

// waitReady polls the node's RPC until it answers (up to 20 s).
func (m *NodeManager) waitReady(nd *node) {
	defer close(nd.ready)
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := m.cli(ctx, nd.rpcPort, "peer", "list")
		cancel()
		if err == nil {
			return
		}
		if !nd.alive() {
			nd.err = fmt.Errorf("easytier node exited during startup: %w", err)
			return
		}
		if time.Now().After(deadline) {
			nd.err = fmt.Errorf("easytier node not ready: %w", err)
			_ = nd.cmd.Process.Kill()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (m *NodeManager) cli(ctx context.Context, rpcPort int, args ...string) ([]byte, error) {
	full := append([]string{"-p", net.JoinHostPort("127.0.0.1", strconv.Itoa(rpcPort)), "-o", "json"}, args...)
	cmd := exec.CommandContext(ctx, m.CLIPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("easytier-cli %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Issue implements Issuer.
func (m *NodeManager) Issue(ctx context.Context, n NetworkSpec, deviceID string, ttl time.Duration) (Credential, error) {
	nd, err := m.node(ctx, n)
	if err != nil {
		return Credential{}, err
	}
	// Generating with an existing id returns the old secret, so every issue gets a new id.
	id := deviceID + "." + strconv.FormatInt(m.now().UnixMilli(), 10)
	out, err := m.cli(ctx, nd.rpcPort, "credential", "generate",
		"--ttl", strconv.FormatInt(int64(ttl/time.Second), 10),
		"--credential-id", id,
		"--groups", DeviceGroup,
		"--allow-relay",
		"--reusable", "false")
	if err != nil {
		return Credential{}, err
	}
	cred, err := ParseGenerated(out)
	if err != nil {
		return Credential{}, err
	}
	if err := m.prune(ctx, nd, deviceID, keepPerDevice); err != nil && m.Log != nil {
		m.Log.Warn("prune old device credentials", "device", deviceID, "err", err)
	}
	return cred, nil
}

// Revoke implements Issuer: every credential of the device, which disconnects it.
func (m *NodeManager) Revoke(ctx context.Context, n NetworkSpec, deviceID string) error {
	nd, err := m.node(ctx, n)
	if err != nil {
		return err
	}
	return m.prune(ctx, nd, deviceID, 0)
}

// prune revokes all but the newest `keep` credentials of a device.
func (m *NodeManager) prune(ctx context.Context, nd *node, deviceID string, keep int) error {
	out, err := m.cli(ctx, nd.rpcPort, "credential", "list")
	if err != nil {
		return err
	}
	ids, err := ParseCredentialIDs(out)
	if err != nil {
		return err
	}
	for _, id := range StaleCredentialIDs(ids, deviceID, keep) {
		if _, err := m.cli(ctx, nd.rpcPort, "credential", "revoke", id); err != nil {
			return err
		}
	}
	return nil
}

// Close stops every node.
func (m *NodeManager) Close() {
	m.mu.Lock()
	m.closed = true
	nodes := m.nodes
	m.nodes = nil
	m.mu.Unlock()
	for _, nd := range nodes {
		if nd.alive() {
			_ = nd.cmd.Process.Kill()
		}
		<-nd.exited
	}
}

// ---------------------------------------------------------------- parsing

// flexInt accepts EasyTier's int64 either as a JSON number (v2.6) or a string (v2.7).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("expiry_unix %s: %w", b, err)
	}
	*f = flexInt(v)
	return nil
}

// ParseGenerated reads `easytier-cli -o json credential generate` output.
func ParseGenerated(out []byte) (Credential, error) {
	var g struct {
		ID     string  `json:"credential_id"`
		Secret string  `json:"credential_secret"`
		Expiry flexInt `json:"expiry_unix"`
	}
	if err := json.Unmarshal(out, &g); err != nil {
		return Credential{}, fmt.Errorf("parse credential: %w", err)
	}
	if g.Secret == "" || g.Expiry == 0 {
		return Credential{}, errors.New("parse credential: missing secret or expiry")
	}
	return Credential{Secret: g.Secret, ExpiresAt: time.Unix(int64(g.Expiry), 0).UTC()}, nil
}

// ParseCredentialIDs reads `easytier-cli -o json credential list` output ("{}" when empty).
func ParseCredentialIDs(out []byte) ([]string, error) {
	var l struct {
		Credentials []struct {
			ID string `json:"credential_id"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, fmt.Errorf("parse credential list: %w", err)
	}
	ids := make([]string, 0, len(l.Credentials))
	for _, c := range l.Credentials {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// StaleCredentialIDs returns the device's credential ids ("<deviceID>.<unix ms>")
// except the newest `keep`. Ids of other devices are never returned.
func StaleCredentialIDs(ids []string, deviceID string, keep int) []string {
	type entry struct {
		id string
		ms int64
	}
	var mine []entry
	for _, id := range ids {
		suffix, ok := strings.CutPrefix(id, deviceID+".")
		if !ok {
			continue
		}
		ms, err := strconv.ParseInt(suffix, 10, 64)
		if err != nil {
			continue
		}
		mine = append(mine, entry{id, ms})
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].ms > mine[j].ms })
	var stale []string
	for i, e := range mine {
		if i >= keep {
			stale = append(stale, e.id)
		}
	}
	return stale
}

func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ServerAddress is the server node's address in a network (host .1).
func ServerAddress(subnet netip.Prefix) netip.Addr {
	return HostAddress(subnet, 1).Addr()
}
