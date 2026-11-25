package et

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net/netip"
)

// Pool is the range user networks are carved from. 10.126.126.0/24 (EasyTier's own
// default) and 100.64.0.0/10 (Tailscale / CGNAT) are outside it by construction.
var Pool = netip.MustParsePrefix("10.250.0.0/16")

// ErrNoFreeSubnet means every /24 in Pool overlaps something the device reported.
var ErrNoFreeSubnet = errors.New("et: no free /24 in pool")

// MaxOccupied bounds how many local prefixes a client may report.
const MaxOccupied = 64

// ChooseSubnet picks a random /24 from Pool (10.250.1.0 to 10.250.254.0) that does not
// overlap any occupied prefix. Random choice keeps collisions with a user's other
// private networks unlikely even when a later device reports a range the first one
// did not have.
func ChooseSubnet(occupied []netip.Prefix) (netip.Prefix, error) {
	var free []netip.Prefix
	base := Pool.Addr().As4()
	for third := 1; third <= 254; third++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{base[0], base[1], byte(third), 0}), 24)
		if !overlapsAny(p, occupied) {
			free = append(free, p)
		}
	}
	if len(free) == 0 {
		return netip.Prefix{}, ErrNoFreeSubnet
	}
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(free))))
	if err != nil {
		return netip.Prefix{}, err
	}
	return free[i.Int64()], nil
}

func overlapsAny(p netip.Prefix, occupied []netip.Prefix) bool {
	for _, o := range occupied {
		if p.Overlaps(o) {
			return true
		}
	}
	return false
}

// HostAddress returns the device address inside subnet, e.g. 10.250.17.3/24 for host 3.
func HostAddress(subnet netip.Prefix, host int) netip.Prefix {
	a := subnet.Masked().Addr().As4()
	a[3] = byte(host)
	return netip.PrefixFrom(netip.AddrFrom4(a), subnet.Bits())
}

// ParseOccupied validates prefixes reported by a client. Only IPv4 is relevant to the
// virtual network; IPv6 entries are ignored.
func ParseOccupied(in []string) ([]netip.Prefix, error) {
	if len(in) > MaxOccupied {
		return nil, errors.New("too many occupied prefixes")
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		if p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// NewNetworkName returns an opaque, unguessable network name that does not reveal
// the user.
func NewNetworkName() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "mrd-" + hex.EncodeToString(b)
}

// NewNetworkSecret returns a fresh 256-bit network secret.
func NewNetworkSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
