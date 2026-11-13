package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var domainLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// E1 certifies stable SFA builds independently of prerelease builds.
func supports1144(bound string, minimum bool) bool {
	parts := strings.Split(bound, ".")
	if len(parts) != 3 {
		return false
	}
	var numbers [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return false
		}
		numbers[i] = n
	}
	order := slices.Compare(numbers[:], []int{1, 14, 4})
	return minimum && order <= 0 || !minimum && order >= 0
}

func ValidEndpoint(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// RenderSFA1144 renders the bound, approved revision in one database snapshot.
// The caller owns the returned profile bytes and must clear them after delivery.
func (r *Registry) RenderSFA1144(ctx context.Context, userID, domain string) ([]byte, error) {
	if !ValidEndpoint(domain) {
		return nil, errors.New("invalid endpoint domain")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var profileID string
	return r.renderSFA(ctx, tx, userID, domain, &profileID)
}

// IssueSFA1144 commits the disclosure record before releasing any profile bytes.
func (r *Registry) IssueSFA1144(ctx context.Context, token, userID, domain string) ([]byte, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := status.SessionOwner(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	if !status.ValidID(userID) || !ValidEndpoint(domain) {
		return nil, sql.ErrNoRows
	}
	var profileID string
	blob, err := r.renderSFA(ctx, tx, userID, domain, &profileID)
	if err != nil {
		return nil, err
	}
	var issued string
	err = tx.QueryRowContext(ctx, `UPDATE user_profiles SET last_issued_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? RETURNING last_issued_at`, profileID).Scan(&issued)
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO profile_issuance(event,admin_id,profile_id,issued_at) VALUES('PROFILE_ISSUED',?,?,?)", actor, profileID, issued)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(blob)
		return nil, err
	}
	return blob, nil
}

func (r *Registry) renderSFA(ctx context.Context, tx *sql.Tx, userID, domain string, profileID *string) ([]byte, error) {
	var login, body, digest, min string
	var max sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT u.login,v.body_json,v.sha256,v.min_version,v.max_version,p.id
 FROM users u JOIN user_profiles p ON p.user_id=u.id JOIN template_revisions v ON v.id=p.template_revision_id
 JOIN profile_templates t ON t.id=v.template_id WHERE u.id=? AND u.status='active'
 AND p.target_client IN ('sfa','sfa-1.14.4') AND v.client_family='sfa' AND v.status='approved' AND t.enabled=1
 ORDER BY CASE p.target_client WHEN 'sfa-1.14.4' THEN 0 ELSE 1 END LIMIT 1`, userID).Scan(&login, &body, &digest, &min, &max, profileID)
	if err != nil {
		return nil, err
	}
	if !supports1144(min, true) || max.Valid && !supports1144(max.String, false) {
		return nil, errors.New("unsupported SFA version")
	}
	sum := sha256.Sum256([]byte(body))
	if digest != hex.EncodeToString(sum[:]) {
		return nil, errors.New("template digest mismatch")
	}
	var profile map[string]json.RawMessage
	var outbounds []map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &profile) != nil || json.Unmarshal(profile["outbounds"], &outbounds) != nil {
		return nil, errors.New("invalid SFA template")
	}
	var proxy map[string]json.RawMessage
	for _, outbound := range outbounds {
		if string(outbound["type"]) == `"naive"` {
			if proxy != nil {
				return nil, errors.New("ambiguous Naive outbound")
			}
			proxy = outbound
		}
	}
	if string(proxy["server"]) != `"DEPLOYMENT_DOMAIN"` || string(proxy["username"]) != `"MASTER_USERNAME"` || string(proxy["password"]) != `"GENERATED_AT_INSTALLATION"` {
		return nil, errors.New("invalid Naive template fields")
	}
	secret, err := r.openForPurpose(ctx, tx, userID, RenderProfile)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	proxy["server"], _ = json.Marshal(domain)
	proxy["username"], _ = json.Marshal(login)
	proxy["password"], _ = json.Marshal(string(secret))
	defer clear(proxy["password"])
	profile["outbounds"], err = json.Marshal(outbounds)
	if err != nil {
		return nil, err
	}
	defer clear(profile["outbounds"])
	return json.Marshal(profile)
}
