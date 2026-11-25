package store

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is a Store kept in process memory. It enforces the same uniqueness and
// visibility rules as the MySQL store.
type Memory struct {
	mu       sync.Mutex
	users    map[string]User
	devices  map[string]Device
	networks map[string]Network
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{users: map[string]User{}, devices: map[string]Device{}, networks: map[string]Network{}}
}

var _ Store = (*Memory)(nil)

func (m *Memory) UpsertUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.users[u.Sub]; ok {
		old.DisplayName, old.UpdatedAt = u.DisplayName, u.UpdatedAt
		m.users[u.Sub] = old
		return nil
	}
	m.users[u.Sub] = u
	return nil
}

func (m *Memory) GetUser(_ context.Context, sub string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[sub]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) CreateDevice(_ context.Context, d Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[d.UserSub]; !ok {
		return ErrNotFound
	}
	if _, ok := m.devices[d.ID]; ok {
		return ErrConflict
	}
	for _, o := range m.devices {
		if bytes.Equal(o.TokenHash, d.TokenHash) ||
			(o.UserSub == d.UserSub && bytes.Equal(o.PublicKey, d.PublicKey)) ||
			(d.ETHost != 0 && o.UserSub == d.UserSub && o.ETHost == d.ETHost) {
			return ErrConflict
		}
	}
	m.devices[d.ID] = clone(d)
	return nil
}

func (m *Memory) GetDevice(_ context.Context, userSub, id string) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.UserSub != userSub {
		return Device{}, ErrNotFound
	}
	return clone(d), nil
}

func (m *Memory) DeviceByTokenHash(_ context.Context, tokenHash []byte) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.devices {
		if bytes.Equal(d.TokenHash, tokenHash) {
			return clone(d), nil
		}
	}
	return Device{}, ErrNotFound
}

func (m *Memory) ListDevices(_ context.Context, userSub string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for _, d := range m.devices {
		if d.UserSub == userSub {
			out = append(out, clone(d))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *Memory) RenameDevice(_ context.Context, userSub, id, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.UserSub != userSub {
		return ErrNotFound
	}
	d.Name = name
	m.devices[id] = d
	return nil
}

func (m *Memory) DeleteDevice(_ context.Context, userSub, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.UserSub != userSub {
		return ErrNotFound
	}
	delete(m.devices, id)
	return nil
}

func (m *Memory) TouchDevice(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	d.LastSeenAt = at
	m.devices[id] = d
	return nil
}

func (m *Memory) AssignETHost(_ context.Context, userSub, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.UserSub != userSub {
		return 0, ErrNotFound
	}
	if d.ETHost != 0 {
		return d.ETHost, nil
	}
	used := map[int]bool{}
	for _, o := range m.devices {
		if o.UserSub == userSub && o.ETHost != 0 {
			used[o.ETHost] = true
		}
	}
	for h := FirstETHost; h <= LastETHost; h++ {
		if !used[h] {
			d.ETHost = h
			m.devices[id] = d
			return h, nil
		}
	}
	return 0, ErrFull
}

func (m *Memory) GetNetwork(_ context.Context, userSub string) (Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.networks[userSub]
	if !ok {
		return Network{}, ErrNotFound
	}
	n.SecretSealed = bytes.Clone(n.SecretSealed)
	return n, nil
}

func (m *Memory) CreateNetwork(_ context.Context, n Network) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[n.UserSub]; !ok {
		return ErrNotFound
	}
	if _, ok := m.networks[n.UserSub]; ok {
		return ErrConflict
	}
	for _, o := range m.networks {
		if o.NetworkName == n.NetworkName || (n.ListenPort != 0 && o.ListenPort == n.ListenPort) {
			return ErrConflict
		}
	}
	n.SecretSealed = bytes.Clone(n.SecretSealed)
	m.networks[n.UserSub] = n
	return nil
}

func (m *Memory) ListNetworks(_ context.Context) ([]Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Network{}
	for _, n := range m.networks {
		n.SecretSealed = bytes.Clone(n.SecretSealed)
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NetworkName < out[j].NetworkName })
	return out, nil
}

func clone(d Device) Device {
	d.PublicKey = bytes.Clone(d.PublicKey)
	d.TokenHash = bytes.Clone(d.TokenHash)
	return d
}
