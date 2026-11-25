package store_test

import (
	"testing"

	"moon-remote/server/internal/store"
	"moon-remote/server/internal/store/storetest"
)

func TestMemoryContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}
