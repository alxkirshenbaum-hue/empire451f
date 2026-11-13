package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

const Client1144 = "sfa-1.14.4"
const ClientAlpha13 = "sfa-1.15-alpha13"
const RoutingWarning = "Requires SFA 1.15.0-alpha.13. Routes selected Russian resources and other Download Manager traffic directly; OpenAI downloads stay on the VPN. Compatibility must be verified on your device."

var ErrTemplateIncompatible = errors.New("TEMPLATE_INCOMPATIBLE")

type ProfileOptions struct {
	Client      string
	RUDM        bool
	Acknowledge bool
}

func (o ProfileOptions) variant() (string, error) {
	if o.Client != Client1144 && o.Client != ClientAlpha13 {
		return "", ErrTemplateIncompatible
	}
	if o.RUDM {
		if o.Client != ClientAlpha13 || !o.Acknowledge {
			return "", ErrTemplateIncompatible
		}
		return "ru_download_manager", nil
	}
	return "base", nil
}
func exactStrings(v any, want []string) bool {
	list, ok := v.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	got := make([]string, len(list))
	for i, x := range list {
		var ok bool
		got[i], ok = x.(string)
		if !ok {
			return false
		}
	}
	slices.Sort(got)
	expect := slices.Clone(want)
	slices.Sort(expect)
	return slices.Equal(got, expect)
}

// DeriveBaseRouting removes only the reviewed combined RU/DM policy. Unknown
// shapes fail closed rather than silently deleting unrelated routing rules.
func DeriveBaseRouting(body []byte) ([]byte, error) {
	var profile map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&profile) != nil {
		return nil, ErrTemplateIncompatible
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, ErrTemplateIncompatible
	}
	route, ok := profile["route"].(map[string]any)
	if !ok {
		return nil, ErrTemplateIncompatible
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, ErrTemplateIncompatible
	}
	kept := make([]any, 0, len(rules))
	panel, private := -1, -1
	dmCount, ruCount := 0, 0
	for _, value := range rules {
		rule, ok := value.(map[string]any)
		if !ok {
			return nil, ErrTemplateIncompatible
		}
		if _, exists := rule["package_name_regex"]; exists {
			return nil, ErrTemplateIncompatible
		}
		if packages, exists := rule["package_name"]; exists {
			if !exactStrings(packages, []string{"com.android.providers.downloads", "com.android.providers.downloads.ui"}) {
				return nil, ErrTemplateIncompatible
			}
			dmCount++
			continue
		}
		if suffix, exists := rule["domain_suffix"]; exists && exactStrings(suffix, []string{".ru", ".su", ".xn--p1ai"}) {
			if len(rule) != 3 || rule["action"] != "route" || rule["outbound"] != "direct" {
				return nil, ErrTemplateIncompatible
			}
			ruCount++
			continue
		}
		if sets, exists := rule["rule_set"]; exists && exactStrings(sets, []string{"geosite-ru", "geoip-ru"}) {
			if len(rule) != 3 || rule["action"] != "route" || rule["outbound"] != "direct" {
				return nil, ErrTemplateIncompatible
			}
			ruCount++
			continue
		}
		if exactStrings(rule["domain"], []string{"panel.home.arpa"}) {
			if panel >= 0 || rule["action"] != "route" || rule["outbound"] != "naive-out" {
				return nil, ErrTemplateIncompatible
			}
			panel = len(kept)
		}
		if rule["ip_is_private"] == true {
			private = len(kept)
		}
		if rule["outbound"] == "direct" && rule["ip_is_private"] != true {
			return nil, ErrTemplateIncompatible
		}
		kept = append(kept, rule)
	}
	if dmCount != 2 || ruCount != 2 || panel < 0 || private >= 0 && panel > private || route["final"] != "naive-out" {
		return nil, ErrTemplateIncompatible
	}
	route["rules"] = kept
	sets, ok := route["rule_set"].([]any)
	if !ok {
		return nil, ErrTemplateIncompatible
	}
	retained := make([]any, 0, len(sets))
	removed := 0
	for _, value := range sets {
		set, ok := value.(map[string]any)
		if !ok {
			return nil, ErrTemplateIncompatible
		}
		if set["tag"] == "geosite-ru" || set["tag"] == "geoip-ru" {
			removed++
			continue
		}
		retained = append(retained, set)
	}
	if removed != 2 {
		return nil, ErrTemplateIncompatible
	}
	if len(retained) == 0 {
		delete(route, "rule_set")
	} else {
		route["rule_set"] = retained
	}
	return json.Marshal(profile)
}

// InstallRoutingVariants approves immutable deterministic derivatives of the
// explicitly reviewed source checksum. Existing bindings/revisions are untouched.
func (r *Registry) InstallRoutingVariants(ctx context.Context, source, approved string) (map[string]string, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var body, hash, template string
	err = tx.QueryRowContext(ctx, "SELECT body_json,sha256,template_id FROM template_revisions WHERE id=? AND status='approved' AND client_family='sfa'", source).Scan(&body, &hash, &template)
	if err != nil {
		return nil, err
	}
	if hash != approved || digest([]byte(body)) != approved {
		return nil, ErrLegacyDrift
	}
	base, err := DeriveBaseRouting([]byte(body))
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, variant := range []string{"base", "ru_download_manager"} {
		candidate := []byte(body)
		minimum := "1.15.0-alpha.13"
		var maximum any = minimum
		if variant == "base" {
			candidate = base
			minimum = "1.14.4"
			maximum = nil
		}
		checksum := digest(candidate)
		var revision, saved, state, stored, storedMin string
		var storedMax sql.NullString
		err = tx.QueryRowContext(ctx, "SELECT v.id,v.sha256,v.status,v.body_json,v.min_version,v.max_version FROM profile_routing_variants m JOIN template_revisions v ON v.id=m.revision_id WHERE m.source_revision_id=? AND m.variant=?", source, variant).Scan(&revision, &saved, &state, &stored, &storedMin, &storedMax)
		if err == nil {
			if saved != checksum || state != "approved" || stored != string(candidate) || storedMin != minimum || storedMax.Valid != (maximum != nil) || storedMax.Valid && storedMax.String != maximum {
				return nil, ErrLegacyDrift
			}
			result[variant] = revision
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		revision = id()
		_, err = tx.ExecContext(ctx, "INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,max_version,body_json,sha256,status,created_at,approved_at) VALUES(?,?,?,'sfa',?,?,?,?,'approved',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)", revision, template, "w6-"+variant+"-"+checksum[:16], minimum, maximum, string(candidate), checksum)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO profile_routing_variants VALUES(?,?,?)", source, variant, revision); err != nil {
			return nil, err
		}
		result[variant] = revision
	}
	return result, tx.Commit()
}
