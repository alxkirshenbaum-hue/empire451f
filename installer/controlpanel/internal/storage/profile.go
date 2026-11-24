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

// WithVPNPanelDestination adds only the panel's HTTP(S) destinations to Naive.
// It leaves the outbound and its DNS bootstrap unchanged.
func WithVPNPanelDestination(body []byte, domain string, entryIP string) ([]byte, error) {
	if !ValidEndpoint(domain) {
		return nil, errors.New("invalid panel domain")
	}
	if entryIP != "" && (net.ParseIP(entryIP) == nil || net.ParseIP(entryIP).To4() == nil || strings.Contains(entryIP, ":")) {
		return nil, errors.New("invalid panel IPv4")
	}
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(body, &profile); err != nil || profile == nil {
		return nil, errors.New("invalid profile")
	}
	exact := func(raw json.RawMessage, value string) bool {
		var values []string
		return json.Unmarshal(raw, &values) == nil && len(values) == 1 && values[0] == value
	}
	for _, section := range []string{"dns", "route"} {
		var object map[string]json.RawMessage
		if raw, ok := profile[section]; ok {
			if json.Unmarshal(raw, &object) != nil || object == nil {
				return nil, errors.New("invalid profile section")
			}
		} else {
			object = make(map[string]json.RawMessage)
		}
		var rules []map[string]json.RawMessage
		if raw, ok := object["rules"]; ok && json.Unmarshal(raw, &rules) != nil {
			return nil, errors.New("invalid profile rules")
		}
		kept := make([]map[string]json.RawMessage, 0, len(rules)+2)
		if section == "route" {
			add := func(key, value string) {
				raw, _ := json.Marshal(map[string]any{key: []string{value}, "network": "tcp", "port": []int{80, 443}, "action": "route", "outbound": "naive-out"})
				var rule map[string]json.RawMessage
				_ = json.Unmarshal(raw, &rule)
				kept = append(kept, rule)
			}
			add("domain", domain)
			if entryIP != "" {
				add("ip_cidr", entryIP+"/32")
			}
		}
		for _, rule := range rules {
			if exact(rule["domain"], "panel.home.arpa") || section == "route" && exact(rule["ip_cidr"], "192.0.2.119/32") {
				continue
			}
			kept = append(kept, rule)
		}
		if section == "route" || object["rules"] != nil {
			object["rules"], _ = json.Marshal(kept)
		}
		if section == "dns" && object["servers"] != nil {
			var servers []map[string]json.RawMessage
			if json.Unmarshal(object["servers"], &servers) != nil {
				return nil, errors.New("invalid DNS servers")
			}
			keptServers := make([]map[string]json.RawMessage, 0, len(servers))
			for _, server := range servers {
				if string(server["tag"]) != `"panel-dns"` {
					keptServers = append(keptServers, server)
				}
			}
			object["servers"], _ = json.Marshal(keptServers)
		}
		if section == "route" || profile[section] != nil {
			profile[section], _ = json.Marshal(object)
		}
	}
	return json.Marshal(profile)
}

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
	return r.RenderProfile(ctx, userID, domain, ProfileOptions{Client: Client1144})
}
func (r *Registry) RenderProfile(ctx context.Context, userID, domain string, options ProfileOptions) ([]byte, error) {
	if _, err := options.variant(); err != nil {
		return nil, err
	}
	if !ValidEndpoint(domain) {
		return nil, errors.New("invalid endpoint domain")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var profileID string
	var revision string
	return r.renderSFA(ctx, tx, userID, domain, &profileID, options, &revision)
}

// IssueSFA1144 commits the disclosure record before releasing any profile bytes.
func (r *Registry) IssueSFA1144(ctx context.Context, token, userID, domain string) ([]byte, error) {
	return r.IssueProfile(ctx, token, userID, domain, ProfileOptions{Client: Client1144})
}
func (r *Registry) IssueProfile(ctx context.Context, token, userID, domain string, options ProfileOptions) ([]byte, error) {
	variant, err := options.variant()
	if err != nil {
		return nil, err
	}
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
	var revision string
	blob, err := r.renderSFA(ctx, tx, userID, domain, &profileID, options, &revision)
	if err != nil {
		return nil, err
	}
	var issued string
	err = tx.QueryRowContext(ctx, `UPDATE user_profiles SET last_issued_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? RETURNING last_issued_at`, profileID).Scan(&issued)
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO profile_issuance(event,admin_id,profile_id,issued_at,target_client,routing_variant,revision_id,profile_sha256) VALUES('PROFILE_ISSUED',?,?,?,?,?,?,?)", actor, profileID, issued, options.Client, variant, revision, digest(blob))
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

func (r *Registry) renderSFA(ctx context.Context, tx *sql.Tx, userID, domain string, profileID *string, options ProfileOptions, selected *string) ([]byte, error) {
	var login, body, checksum, min, source string
	var max sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT u.login,v.body_json,v.sha256,v.min_version,v.max_version,p.id,v.id
 FROM users u JOIN user_profiles p ON p.user_id=u.id JOIN template_revisions v ON v.id=p.template_revision_id
 JOIN profile_templates t ON t.id=v.template_id WHERE u.id=? AND u.status='active' AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.target_type='user' AND o.target_id=u.id AND o.status IN ('reconcile_required','rollback_running','running','verifying'))
 AND p.target_client IN ('sfa','sfa-1.14.4') AND v.client_family='sfa' AND v.status='approved' AND t.enabled=1
 ORDER BY CASE p.target_client WHEN 'sfa-1.14.4' THEN 0 ELSE 1 END LIMIT 1`, userID).Scan(&login, &body, &checksum, &min, &max, profileID, &source)
	if err != nil {
		return nil, err
	}
	if digest([]byte(body)) != checksum {
		return nil, errors.New("template digest mismatch")
	}
	variant, err := options.variant()
	if err != nil {
		return nil, err
	}
	// An existing base binding resolves to the same approved source family.
	var root string
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE((SELECT source_revision_id FROM profile_routing_variants WHERE revision_id=?),?)", source, source).Scan(&root); err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, "SELECT v.id,v.body_json,v.sha256,v.min_version,v.max_version FROM profile_routing_variants m JOIN template_revisions v ON v.id=m.revision_id JOIN template_revisions s ON s.id=m.source_revision_id WHERE m.source_revision_id=? AND m.variant=? AND m.policy_version=? AND v.status='approved' AND s.status='approved'", root, variant, RoutingPolicyVersion).Scan(selected, &body, &checksum, &min, &max)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTemplateIncompatible
	}
	if err != nil {
		return nil, err
	}
	if variant == "base" {
		if !supports1144(min, true) || max.Valid && !supports1144(max.String, false) {
			return nil, ErrTemplateIncompatible
		}
	} else if min != "1.15.0-alpha.13" || !max.Valid || max.String != "1.15.0-alpha.13" {
		return nil, ErrTemplateIncompatible
	}
	sum := sha256.Sum256([]byte(body))
	if checksum != hex.EncodeToString(sum[:]) {
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
	blob, err := json.Marshal(profile)
	if err != nil || options.PanelDomain == "" {
		return blob, err
	}
	defer clear(blob)
	return WithVPNPanelDestination(blob, options.PanelDomain, options.PanelEntryIP)
}

// BindMissingLegacyProfiles repairs only absent imported-user bindings. The caller
// must hold the installation writer lock and supply the explicitly approved source.
func (r *Registry) BindMissingLegacyProfiles(ctx context.Context, source, approved string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var body, checksum string
	err = tx.QueryRowContext(ctx, `SELECT v.body_json,v.sha256 FROM template_revisions v
 JOIN profile_templates t ON t.id=v.template_id
 WHERE v.id=? AND v.status='approved' AND v.client_family='sfa' AND v.min_version='1.14.4'
 AND t.enabled=1 AND t.slug='sfa'
 AND NOT EXISTS(SELECT 1 FROM profile_routing_variants WHERE revision_id=v.id)`, source).Scan(&body, &checksum)
	if err != nil {
		return err
	}
	if checksum != approved || digest([]byte(body)) != approved {
		return ErrLegacyDrift
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.id FROM users u WHERE u.source='legacy_import'
 AND u.status IN ('active','disabled','provisioning')
 AND NOT EXISTS(SELECT 1 FROM user_profiles p WHERE p.user_id=u.id)`)
	if err != nil {
		return err
	}
	var users []string
	for rows.Next() {
		var user string
		if err = rows.Scan(&user); err != nil {
			rows.Close()
			return err
		}
		users = append(users, user)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, user := range users {
		if _, err = tx.ExecContext(ctx, "INSERT INTO user_profiles(id,user_id,template_revision_id,target_client) VALUES(?,?,?,'sfa-1.14.4')", id(), user, source); err != nil {
			return err
		}
	}
	return tx.Commit()
}
