package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func ownerCookie() (http.Cookie, error) {
	var cookie http.Cookie
	path := os.Getenv("VPNCTL_SESSION_FILE")
	if path == "" {
		return cookie, errors.New("Set VPNCTL_SESSION_FILE to a private session file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return cookie, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return cookie, errors.New("Unsafe session file path")
	}
	dir, err := os.Lstat(filepath.Dir(absolute))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return cookie, errors.New("Session directory must be private")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 514 {
		return cookie, errors.New("Session file must be private")
	}
	raw, err := os.ReadFile(absolute)
	if err != nil {
		return cookie, err
	}
	defer clear(raw)
	token := strings.TrimSpace(string(raw))
	if len(token) == 0 || len(token) > 512 {
		return cookie, errors.New("Invalid session file")
	}
	cookie = http.Cookie{Name: "session", Value: token}
	return cookie, cookie.Valid()
}
func ownerCLIMode(args []string) bool {
	if len(args) < 2 {
		return false
	}
	for _, arg := range args {
		if arg == "--installation" || strings.HasPrefix(arg, "--installation=") {
			return false
		}
	}
	allowed := map[string]string{
		"user": "|list|show|create|rename|disable|enable|delete|history|check|",
		"cred": "|status|rotate|revoke|", "profile": "|download|", "template": "|list|",
		"operation": "|list|", "audit": "|list|", "backup": "|list|", "system": "|show|",
	}
	return strings.Contains(allowed[args[0]], "|"+args[1]+"|")
}
func ownerCLI(args []string, out, stderr io.Writer) int {
	group, action := args[0], args[1]
	flags := flag.NewFlagSet(group+" "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var user string
	rest := args[2:]
	needsID := group == "user" && action != "list" && action != "create" || group == "cred" || group == "profile"
	if needsID {
		if len(rest) == 0 || !status.ValidID(rest[0]) {
			fmt.Fprintln(stderr, "Expected user UUID")
			return 2
		}
		user = rest[0]
		rest = rest[1:]
	}
	login := flags.String("login", "", "Exact immutable login")
	name := flags.String("display-name", "", "Display name")
	template := flags.String("template", "", "Approved base template UUID")
	clientVersion := flags.String("client", storage.Client1144, "Exact supported SFA client")
	expected := flags.Int64("expected-version", 0, "Expected row version")
	reason := flags.String("reason", "", "Reason for change")
	confirmation := flags.Bool("confirm-delete", false, "Confirm tombstone")
	key := flags.String("idempotency-key", "", "Stable request UUID")
	output := flags.String("output", "", "Private output file")
	optional := flags.Bool("ru-dm", false, "Opt in to RU / Download Manager")
	acknowledged := flags.Bool("acknowledge", false, "Acknowledge optional routing warning")
	search := flags.String("search", "", "Case-sensitive search")
	filter := flags.String("status", "", "Recorded user status")
	limit := flags.Int("limit", 100, "Page size")
	cursor := flags.String("cursor", "", "Page cursor")
	machine := flags.Bool("json", false, "JSON response")
	quiet := flags.Bool("quiet", false, "No metadata output")
	if flags.Parse(rest) != nil || flags.NArg() != 0 || *machine && *quiet {
		fmt.Fprintln(stderr, "Invalid command options")
		return 2
	}
	allowedFlags := "|json|quiet|"
	switch group + "/" + action {
	case "user/list":
		allowedFlags += "limit|cursor|search|status|"
	case "user/create":
		allowedFlags += "login|display-name|template|client|idempotency-key|"
	case "user/rename":
		allowedFlags += "display-name|expected-version|idempotency-key|"
	case "user/disable", "user/enable", "cred/rotate", "cred/revoke":
		allowedFlags += "expected-version|reason|idempotency-key|"
	case "user/delete":
		allowedFlags += "expected-version|reason|idempotency-key|confirm-delete|"
	case "profile/download":
		allowedFlags += "client|ru-dm|acknowledge|output|"
	}
	invalid := false
	flags.Visit(func(f *flag.Flag) {
		if !strings.Contains(allowedFlags, "|"+f.Name+"|") {
			invalid = true
		}
	})
	if invalid {
		fmt.Fprintln(stderr, "Option does not apply to this command")
		return 2
	}
	method, path := "GET", ""
	var body any
	switch group {
	case "user":
		switch action {
		case "list":
			q := url.Values{"limit": {fmt.Sprint(*limit)}, "search": {*search}, "status": {*filter}}
			if *cursor != "" {
				q.Set("cursor", *cursor)
			}
			path = "/api/v1/users?" + q.Encode()
		case "show":
			path = "/api/v1/users/" + user
		case "history":
			path = "/api/v1/users/" + user + "/history"
		case "check":
			method, path, body = "POST", "/api/v1/users/"+user+"/validate", map[string]any{}
		case "create":
			if *login == "" || !status.ValidID(*template) || (*clientVersion != storage.Client1144 && *clientVersion != storage.ClientAlpha13) {
				fmt.Fprintln(stderr, "Expected login, approved template and supported client")
				return 2
			}
			if *name == "" {
				*name = *login
			}
			method, path, body = "POST", "/api/v1/users", map[string]any{"login": *login, "display_name": *name, "template_revision_id": *template, "target_client": *clientVersion}
		case "rename":
			method, path, body = "PATCH", "/api/v1/users/"+user, map[string]any{"display_name": *name, "expected_version": *expected}
		case "disable", "enable", "delete":
			method, path, body = "POST", "/api/v1/users/"+user+"/"+action, map[string]any{"expected_version": *expected, "reason": *reason, "confirm_delete": *confirmation}
			if action == "delete" {
				method, path = "DELETE", "/api/v1/users/"+user
				if !*confirmation {
					fmt.Fprintln(stderr, "Explicit --confirm-delete required")
					return 2
				}
			}
		}
	case "cred":
		path = "/api/v1/users/" + user + "/credential"
		if action != "status" {
			method = "POST"
			path += "/" + action
			body = map[string]any{"expected_version": *expected, "reason": *reason}
		}
	case "profile":
		if *output == "" || (*clientVersion != storage.Client1144 && *clientVersion != storage.ClientAlpha13) || *optional && (*clientVersion != storage.ClientAlpha13 || !*acknowledged) {
			fmt.Fprintln(stderr, "Expected private output and compatible client/routing options")
			return 2
		}
		q := url.Values{"client": {*clientVersion}}
		if *optional {
			q.Set("ru_dm", "1")
			q.Set("ack", "1")
			fmt.Fprintln(stderr, storage.RoutingWarning)
		}
		path = "/api/v1/users/" + user + "/profiles/download?" + q.Encode()
	case "template":
		path = "/api/v1/templates"
	case "operation":
		path = "/api/v1/operations"
	case "audit":
		path = "/api/v1/audits"
	case "backup":
		path = "/api/v1/backups"
	case "system":
		path = "/api/v1/dashboard"
	}
	mutation := method != "GET" && action != "check"
	if path == "" || mutation && !status.ValidID(*key) || mutation && action != "create" && *expected < 1 {
		fmt.Fprintln(stderr, "Expected stable idempotency key and current row version")
		return 2
	}
	if mutation {
		fmt.Fprintln(stderr, caddy.ApplyNotice)
	}
	cookie, err := ownerCookie()
	if err != nil {
		fmt.Fprintln(stderr, "Private owner session unavailable")
		return 3
	}
	socket := os.Getenv("VPNCTL_SOCKET")
	if socket == "" {
		socket = "/run/vpn-control/api.sock"
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return 2
		}
	}
	req, err := http.NewRequest(method, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return 2
	}
	req.AddCookie(&cookie)
	if method != "GET" {
		req.Header.Set("Origin", auth.Origin)
		req.Header.Set("X-CSRF-Token", auth.CSRF(cookie.Value))
		req.Header.Set("Content-Type", "application/json")
		if mutation {
			req.Header.Set("Idempotency-Key", *key)
		}
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "Local API unavailable; retry mutations with the same idempotency key")
		return 5
	}
	defer response.Body.Close()
	if group == "profile" && response.StatusCode == 200 {
		raw, e := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
		if e != nil || len(raw) > 2*1024*1024 || !json.Valid(raw) {
			clear(raw)
			fmt.Fprintln(stderr, "Invalid profile response")
			return 9
		}
		defer clear(raw)
		target, e := filepath.Abs(*output)
		if e != nil {
			return 2
		}
		parent := filepath.Dir(target)
		resolved, e := filepath.EvalSymlinks(parent)
		info, e2 := os.Lstat(parent)
		if e != nil || e2 != nil || resolved != parent || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			fmt.Fprintln(stderr, "Profile output directory must be private")
			return 3
		}
		f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			fmt.Fprintln(stderr, "Cannot create private profile file; existing files are never replaced")
			return 3
		}
		saved := false
		defer func() {
			f.Close()
			if !saved {
				os.Remove(target)
			}
		}()
		_, e = f.Write(raw)
		if e == nil {
			e = f.Sync()
		}
		e2 = f.Close()
		if e != nil || e2 != nil {
			return 9
		}
		saved = true
		if !*quiet {
			if *machine {
				_ = json.NewEncoder(out).Encode(map[string]string{"path": target, "client": *clientVersion})
			} else {
				fmt.Fprintf(out, "Profile saved: %q\n", target)
			}
		}
		return 0
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 9
	}
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	valid := json.Unmarshal(raw, &envelope) == nil
	if response.StatusCode >= 400 {
		if *machine && valid && envelope.Error != nil {
			fmt.Fprintln(out, string(raw))
		}
		if valid && envelope.Error != nil {
			fmt.Fprintln(stderr, envelope.Error.Code)
		} else {
			fmt.Fprintln(stderr, "Local API rejected the request")
		}
		switch response.StatusCode {
		case 401, 403:
			return 3
		case 409, 412, 423, 428:
			return 4
		case 400, 404, 405, 410, 415, 422:
			return 2
		default:
			return 5
		}
	}
	if !valid || len(envelope.Data) == 0 {
		return 9
	}
	if !*quiet {
		if *machine {
			fmt.Fprintln(out, string(raw))
		} else {
			var indented bytes.Buffer
			if json.Indent(&indented, envelope.Data, "", "  ") != nil {
				return 9
			}
			fmt.Fprintln(out, indented.String())
		}
	}
	if action == "check" {
		return 5
	} // Metadata inspection is not a proven live check.
	return 0
}
