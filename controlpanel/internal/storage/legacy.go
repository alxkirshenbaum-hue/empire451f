package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type LegacyReceipt struct {
	OperationID string `json:"operation_id"`
	Users       int    `json:"staged_users"`
}
type legacyAction struct {
	Login          string
	Kind           string
	Protected      bool
	LegacyAccepted bool `json:"legacy_accepted"`
	Action         string
}
type legacyPlan struct {
	RunID      string `json:"run_id"`
	Generation string `json:"snapshot_sha256"`
	Users      []legacyAction
}

var legacyLogin = regexp.MustCompile("^[A-Za-z0-9_.@-]{1,64}$")

// Read the same fixed inventory as inspect_legacy.py. Passwords used below
// come from the exact clients.json bytes included in the generation digest.
func legacyInputs(dir string) (string, map[string]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", nil, err
	}
	defer root.Close()
	listing, err := root.Open(".")
	if err != nil {
		return "", nil, err
	}
	defer listing.Close()
	entries, err := listing.ReadDir(-1)
	if err != nil {
		return "", nil, err
	}
	names := []string{"auth.caddy", "clients.json", "manifest.json", "master_user.sfa.json"}
	for _, e := range entries {
		name := e.Name()
		if name == "pending.json" || name == "user-rollback.json" {
			return "", nil, errors.New("pending installer transaction")
		}
		if strings.HasPrefix(name, "vpn-") && strings.HasSuffix(name, ".json") {
			names = append(names, name)
		}
	}
	hashes := map[string]string{}
	passwords := map[string]string{}
	for _, name := range names {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return "", nil, errors.New("incomplete snapshot")
		}
		file, err := root.Open(name)
		if err != nil {
			return "", nil, err
		}
		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			return "", nil, err
		}
		hashes[name] = digest(data)
		if name == "clients.json" {
			var exp struct {
				Clients []struct{ Username, Password string }
			}
			err = json.Unmarshal(data, &exp)
			if err == nil {
				for _, user := range exp.Clients {
					passwords[user.Username] = user.Password
				}
			}
		}
		clear(data)
		if err != nil {
			return "", nil, err
		}
	}
	encoded, err := json.Marshal(hashes)
	if err != nil {
		return "", nil, err
	}
	return digest(encoded), passwords, nil
}

// StageLegacy is for an isolated copy of the registry. The transaction records
// operator approval, all encrypted rows, and the receipt as one durable unit.
func (r *Registry) StageLegacy(ctx context.Context, dir, run string) (LegacyReceipt, error) {
	var receipt LegacyReceipt
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	var phase, status, body string
	err = tx.QueryRowContext(ctx, `SELECT r.phase,r.status,d.body FROM legacy_migration_runs r
 JOIN legacy_migration_documents d ON d.run_id=r.id AND d.kind='plan' WHERE r.id=?`, run).Scan(&phase, &status, &body)
	if err != nil {
		return receipt, err
	}
	if phase == "importing" && status == "staged" {
		err = tx.QueryRowContext(ctx, `SELECT id,(SELECT count(*) FROM legacy_migration_items WHERE run_id=? AND imported_user_id IS NOT NULL) FROM operations WHERE actor_id='local-migration' AND idempotency_key=? AND kind='legacy.stage'`, run, run).Scan(&receipt.OperationID, &receipt.Users)
		return receipt, err
	}
	if phase != "planned" || status != "planned" {
		return receipt, errors.New("plan unavailable")
	}
	var plan legacyPlan
	if err = json.Unmarshal([]byte(body), &plan); err != nil || plan.RunID != run {
		return receipt, errors.New("invalid plan")
	}
	generation, passwords, err := legacyInputs(dir)
	if err != nil {
		return receipt, err
	}
	if generation != plan.Generation {
		_, err = tx.ExecContext(ctx, "UPDATE legacy_migration_runs SET phase='reconcile_required',status='stale' WHERE id=?", run)
		if err != nil {
			return receipt, err
		}
		if err = tx.Commit(); err != nil {
			return receipt, err
		}
		return receipt, errors.New("snapshot differs from approved plan")
	}
	var users int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&users); err != nil {
		return receipt, err
	}
	if users != 0 || len(passwords) != len(plan.Users) || len(passwords) > 101 || passwords["master_user"] == "" {
		return receipt, errors.New("staging preconditions failed")
	}
	for i, action := range plan.Users {
		password := passwords[action.Login]
		master := action.Login == "master_user"
		kind := "regular"
		if master {
			kind = "service"
		}
		if !legacyLogin.MatchString(action.Login) || action.Action != "stage_existing_credential" || action.Kind != kind || action.Protected != master || action.LegacyAccepted == loginPattern.MatchString(action.Login) || password == "" {
			return receipt, errors.New("invalid import action")
		}
		if err = r.stageLegacyUser(ctx, tx, run, i+1, action, password); err != nil {
			return receipt, err
		}
	}
	receipt = LegacyReceipt{id(), len(plan.Users)}
	_, err = tx.ExecContext(ctx, `INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,correlation_id,created_at,started_at,finished_at)
 VALUES(?,'local-migration','legacy.stage','migration',?,'succeeded',?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, receipt.OperationID, run, run, generation, receipt.OperationID)
	if err != nil {
		return LegacyReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE legacy_migration_runs SET approved_at=CURRENT_TIMESTAMP,phase='importing',status='staged' WHERE id=?", run)
	if err != nil {
		return LegacyReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return LegacyReceipt{}, err
	}
	return receipt, nil
}

func (r *Registry) stageLegacyUser(ctx context.Context, tx *sql.Tx, run string, number int, a legacyAction, password string) error {
	uid, credential := id(), id()
	plain := []byte(password)
	defer clear(plain)
	nonce, ciphertext, err := r.vault.Encrypt(vault.Binding{UserID: uid, SecretVersion: 1, KeyVersion: uint64(r.keyVersion)}, plain)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO users(id,login,display_name,kind,protected,source,status,created_at,updated_at) VALUES(?,?,?,?,?,'legacy_import','provisioning',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, uid, a.Login, a.Login, a.Kind, a.Protected)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES(?,?,1,?,?,?,?,CURRENT_TIMESTAMP)`, credential, uid, vault.Algorithm, nonce, ciphertext, r.keyVersion)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO user_current_credentials VALUES(?,?,CURRENT_TIMESTAMP)", uid, credential)
	if err != nil {
		return err
	}
	finding := "matched"
	if a.LegacyAccepted {
		finding = "legacy_accepted"
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO legacy_migration_items(run_id,item_no,source_kind,login_exact,finding_code,imported_user_id) VALUES(?,?,'clients',?,?,?)", run, number, a.Login, finding, uid)
	return err
}
