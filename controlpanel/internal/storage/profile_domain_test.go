package storage

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestWithVPNPanelDestination(t *testing.T) {
	body := []byte(`{"outbounds":[{"type":"naive","server":"proxy.example","password":"secret","domain_resolver":"bootstrap"}],"dns":{"servers":[{"tag":"panel-dns"},{"tag":"bootstrap","type":"https","server":"1.1.1.1"}],"rules":[{"domain":["panel.home.arpa"],"server":"panel-dns"},{"domain":["other.example"],"server":"bootstrap"}]},"route":{"final":"direct","rules":[{"domain":["panel.home.arpa"]},{"ip_cidr":["192.0.2.119/32"]},{"protocol":"dns","action":"hijack-dns"}]},"extra":{"number":1234567890123456789}}`)
	got, err := WithVPNPanelDestination(body, "panel.example", "193.233.22.225")
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(body, &before)
	_ = json.Unmarshal(got, &after)
	for _, key := range []string{"outbounds", "extra"} {
		var a, b any
		_ = json.Unmarshal(before[key], &a)
		_ = json.Unmarshal(after[key], &b)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("changed %s", key)
		}
	}
	var route struct {
		Final string           `json:"final"`
		Rules []map[string]any `json:"rules"`
	}
	_ = json.Unmarshal(after["route"], &route)
	if route.Final != "direct" || len(route.Rules) != 3 {
		t.Fatalf("unexpected route: %s", after["route"])
	}
	for i, key := range []string{"domain", "ip_cidr"} {
		want := map[string]any{key: []any{[]string{"panel.example", "193.233.22.225/32"}[i]}, "network": "tcp", "port": []any{float64(80), float64(443)}, "action": "route", "outbound": "naive-out"}
		if !reflect.DeepEqual(route.Rules[i], want) {
			t.Fatalf("unexpected rule: %#v", route.Rules[i])
		}
	}
	var dns struct {
		Servers []map[string]any
		Rules   []map[string]any
	}
	_ = json.Unmarshal(after["dns"], &dns)
	if len(dns.Servers) != 1 || dns.Servers[0]["tag"] != "bootstrap" || len(dns.Rules) != 1 {
		t.Fatalf("unexpected DNS: %s", after["dns"])
	}
	if _, err := WithVPNPanelDestination(body, "panel.example", ""); err != nil {
		t.Fatal(err)
	}
}

func TestWithVPNPanelDestinationRejectsInvalid(t *testing.T) {
	for _, tc := range []struct{ body, domain, ip string }{
		{`{}`, "bad", ""}, {`{}`, "panel.example", "::1"}, {`{}`, "panel.example", "999.1.1.1"}, {`null`, "panel.example", ""}, {`{"route":[]}`, "panel.example", ""},
	} {
		if _, err := WithVPNPanelDestination([]byte(tc.body), tc.domain, tc.ip); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
