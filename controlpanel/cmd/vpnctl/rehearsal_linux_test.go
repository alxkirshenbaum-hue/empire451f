//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// Initializes only the synthetic, preverified baseline in the isolated root.
// This is test code, never linked into vpnctl and never performs MIG-05.
func TestRehearsalFixture(t *testing.T) {
	phase := os.Getenv("VPN_REHEARSAL_FIXTURE")
	if phase == "" {
		t.Skip("isolated root fixture")
	}
	if _, err := os.Stat("/.vpn-control-rehearsal"); err != nil {
		t.Fatal("requires dedicated rehearsal root")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("requires isolated network")
	}
	var fixture struct{ OwnerPassword, Run string }
	data, err := os.ReadFile("/run/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if json.Unmarshal(data, &fixture) != nil {
		t.Fatal("bad fixture")
	}
	ctx := context.Background()
	path := "/var/lib/vpn-control/state.db"
	keyPath := "/var/lib/vpn-control/vault.key"
	if phase == "init" {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("existing registry refused")
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		if err = os.WriteFile(keyPath, key, 0600); err != nil {
			t.Fatal(err)
		}
		v, _ := vault.New(key)
		r, err := storage.Open(ctx, path, v, 1)
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		template, err := os.ReadFile("/work/templates/sfa-profile.json")
		if err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err = db.Exec("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1)"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1.14.4',?,?,'approved',CURRENT_TIMESTAMP)", string(template), fmt.Sprintf("%x", sha256.Sum256(template))); err != nil {
			t.Fatal(err)
		}
		sessions, err := auth.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer sessions.Close()
		if err = sessions.Bootstrap(ctx, "owner", fixture.OwnerPassword); err != nil {
			t.Fatal(err)
		}
	} else if phase == "baseline" {
		// The baseline is initialized only after canonical StageLegacy import.
		db, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		info, err := os.Stat("/var/lib/empire-vpn/lab")
		if err != nil {
			t.Fatal(err)
		}
		identity := info.Sys().(*syscall.Stat_t)
		result, err := tx.Exec("UPDATE legacy_migration_runs SET phase='verified_cutover',status='verified_cutover',report_ref=? WHERE id=? AND phase='importing' AND status='staged'", fmt.Sprintf("installation:%d:%d", identity.Dev, identity.Ino), fixture.Run)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			t.Fatal("fixture import missing")
		}
		if _, err = tx.Exec("UPDATE users SET status='active',row_version=row_version+1 WHERE source='legacy_import' AND status='provisioning'"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("unknown fixture phase")
	}
}
