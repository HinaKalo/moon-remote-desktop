// Package store defines the persistent model of moon-remote-server and an in-memory
// implementation used by tests and local development. The MySQL implementation lives
// in package mysqlstore; both are checked by the shared suite in package storetest.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound means the row does not exist or is not visible to the caller.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict means a uniqueness rule was violated.
	ErrConflict = errors.New("store: conflict")
	// ErrFull means no free EasyTier host number is left in the user's /24.
	ErrFull = errors.New("store: no free address")
)

// DeviceKind says whether an installation can be controlled.
type DeviceKind string

const (
	// KindHost accepts incoming sessions (and can also control others).
	KindHost DeviceKind = "host"
	// KindViewer only controls others.
	KindViewer DeviceKind = "viewer"
)

// Valid reports whether k is a known kind.
func (k DeviceKind) Valid() bool { return k == KindHost || k == KindViewer }

// User is an sso.moonl.cloud account that has used this service.
type User struct {
	Sub         string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Device is one registered installation.
type Device struct {
	ID         string
	UserSub    string
	Name       string
	Kind       DeviceKind
	PublicKey  []byte // Ed25519, 32 bytes
	TokenHash  []byte // SHA-256 of the device token, 32 bytes
	ETHost     int    // 0 = not assigned yet, else 2..254
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// Network is a user's EasyTier network.
type Network struct {
	UserSub      string
	NetworkName  string
	SecretSealed []byte
	CIDR         string // e.g. "10.250.17.0/24"
	// ListenPort is the public port of the network's server-side EasyTier node.
	ListenPort int
	CreatedAt  time.Time
}

// First and last EasyTier host numbers handed to devices; .1 is the server's node.
const (
	FirstETHost = 2
	LastETHost  = 254
)

// Store is the persistence contract. Methods taking userSub only see that user's rows
// and report ErrNotFound for anyone else's, so handlers cannot leak across accounts.
type Store interface {
	// UpsertUser creates the user or refreshes the display name.
	UpsertUser(ctx context.Context, u User) error
	GetUser(ctx context.Context, sub string) (User, error)

	// CreateDevice fails with ErrConflict if the user already registered that public key.
	CreateDevice(ctx context.Context, d Device) error
	GetDevice(ctx context.Context, userSub, id string) (Device, error)
	DeviceByTokenHash(ctx context.Context, tokenHash []byte) (Device, error)
	ListDevices(ctx context.Context, userSub string) ([]Device, error)
	RenameDevice(ctx context.Context, userSub, id, name string) error
	DeleteDevice(ctx context.Context, userSub, id string) error
	TouchDevice(ctx context.Context, id string, at time.Time) error
	// AssignETHost returns the device's host number, assigning the lowest free one
	// on first use. ErrFull when all of 2..254 are taken.
	AssignETHost(ctx context.Context, userSub, id string) (int, error)

	GetNetwork(ctx context.Context, userSub string) (Network, error)
	// CreateNetwork fails with ErrConflict if the user already has one or the name or
	// listen port is taken.
	CreateNetwork(ctx context.Context, n Network) error
	// ListNetworks returns every network (the server starts a node for each).
	ListNetworks(ctx context.Context) ([]Network, error)
}
