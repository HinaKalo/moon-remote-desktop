package mysqlstore_test

// Runs the store contract against a real MySQL 8 database.
// Set MRD_TEST_DSN, e.g. "mrd:pw@tcp(127.0.0.1:3306)/mrd_test", to an empty, disposable
// database; migrations are applied automatically. Skipped when unset.

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"moon-remote/server/internal/db"
	"moon-remote/server/internal/store"
	"moon-remote/server/internal/store/mysqlstore"
	"moon-remote/server/internal/store/storetest"
)

func TestMySQLContract(t *testing.T) {
	dsn := os.Getenv("MRD_TEST_DSN")
	if dsn == "" {
		t.Skip("MRD_TEST_DSN not set")
	}
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{DSN: dsn, MaxOpenConns: 16, MaxIdleConns: 4, ConnMaxLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.Migrate(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	// One shared database: the suite isolates itself with random subjects.
	s := mysqlstore.New(d)
	storetest.Run(t, func(*testing.T) store.Store { return s })
}
