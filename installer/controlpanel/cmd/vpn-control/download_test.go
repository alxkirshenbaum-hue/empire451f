package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestOwnerDownloadsActiveProfile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	cipher, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := storage.Open(ctx, path, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execSQL := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	tpl, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	execSQL("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1)")
	execSQL("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1.14.4',?,?,'approved',CURRENT_TIMESTAMP)", string(tpl), fmt.Sprintf("%x", sha256.Sum256(tpl)))
	if _, err = reg.InstallRoutingVariants(ctx, "r", fmt.Sprintf("%x", sha256.Sum256(tpl))); err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	sessions.EnableProfileDownloads()
	if err = sessions.Bootstrap(ctx, "owner", "synthetic password"); err != nil {
		t.Fatal(err)
	}
	receipt, err := reg.QueueCreate(ctx, "owner", "00000000-0000-4000-8000-000000000001", storage.CreateRequest{Login: "Test-User", DisplayName: "Test User", TemplateRevisionID: "r", TargetClient: "sfa"})
	if err != nil {
		t.Fatal(err)
	}
	reader, e := status.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	mux := http.NewServeMux()
	mux.Handle("/", reader.Handler())
	mux.HandleFunc("GET /api/v1/users/{id}/profiles/download", download(reg, "entry.example"))
	panelRoutes(mux, reg, "00000000-0000-4000-8000-000000000002")
	execSQL("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')", "00000000-0000-4000-8000-000000000002")
	handler := sessions.Handler(mux)
	form := url.Values{"username": {"owner"}, "password": {"synthetic password"}}
	login := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	login.Header.Set("Origin", auth.Origin)
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, login)
	if resp.Code != 303 {
		t.Fatal("login failed")
	}
	cookie := resp.Result().Cookies()[0]
	fetch := func(method string, c *http.Cookie, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/users/"+receipt.UserID+"/profiles/download?client=sfa-1.14.4", nil)
		if c != nil {
			req.AddCookie(c)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != want || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("download status %d, want %d", resp.Code, want)
		}
		return resp
	}
	fetch("GET", nil, 401)
	fetch("GET", cookie, 404)
	var probe *exec.Cmd
	var encoder *json.Encoder
	var probeInput func(string, vault.PlainSecret) error
	if os.Getenv("VPN_TEST_NAIVE_PROBE") == "1" {
		probeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		probe = exec.CommandContext(probeCtx, "python3", "-B", "../../../pilot/issue_probe.py")
		input, err := probe.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := probe.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = probe.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			input.Close()
			if probe.ProcessState == nil {
				probe.Process.Kill()
				probe.Wait()
			}
		}()
		encoder = json.NewEncoder(input)
		probeInput = func(login string, secret vault.PlainSecret) error {
			if err := encoder.Encode([]string{login, string(secret)}); err != nil {
				return err
			}
			line, err := bufio.NewReader(output).ReadString('\n')
			if err != nil || line != "verified\n" {
				t.Fatal("isolated Caddy did not verify the candidate")
			}
			return nil
		}
	}
	execSQL("CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON operations WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END")
	if reg.ApplyCreate(ctx, receipt, func(_ context.Context, login string, secret vault.PlainSecret) error {
		if probeInput != nil {
			return probeInput(login, secret)
		}
		return nil
	}) == nil {
		t.Fatal("expected journal failure")
	}
	fetch("GET", cookie, 404)
	execSQL("DROP TRIGGER reject_finish")
	if err = reg.CompleteVerifiedCreate(ctx, receipt, 1); err != nil {
		t.Fatal(err)
	}
	if err = reg.CompleteVerifiedCreate(ctx, receipt, 1); err != nil {
		t.Fatal("completion replay", err)
	}
	fetch("HEAD", cookie, 405)
	home := httptest.NewRequest("GET", "/", nil)
	home.AddCookie(cookie)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, home)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "/api/v1/users/"+receipt.UserID+"/profiles/download?client=sfa-1.14.4") {
		t.Fatal("profile download link missing")
	}
	execSQL("CREATE TRIGGER reject_audit BEFORE INSERT ON profile_issuance BEGIN SELECT RAISE(ABORT,'fixture'); END")
	fetch("GET", cookie, 503)
	var issued sql.NullString
	if err = db.QueryRow("SELECT last_issued_at FROM user_profiles").Scan(&issued); err != nil || issued.Valid {
		t.Fatal("issuance did not roll back")
	}
	execSQL("DROP TRIGGER reject_audit")
	result := fetch("GET", cookie, 200)
	_, disposition, parseErr := mime.ParseMediaType(result.Header().Get("Content-Disposition"))
	if parseErr != nil || disposition["filename"] != "vpn-Test-User-sfa-1.14.4.json" {
		t.Fatal("profile filename lost exact login/client", disposition, parseErr)
	}
	if probe != nil {
		if err := encoder.Encode(json.RawMessage(result.Body.Bytes())); err != nil {
			t.Fatal(err)
		}
		if err := probe.Wait(); err != nil {
			t.Fatal("downloaded profile failed isolated Naive probe", err)
		}
	}
	var profile struct {
		Outbounds []struct{ Username, Password, Server string }
	}
	if !strings.HasPrefix(result.Header().Get("Content-Disposition"), "attachment;") || json.Unmarshal(result.Body.Bytes(), &profile) != nil || len(profile.Outbounds) == 0 {
		t.Fatal("missing profile attachment")
	}
	secret, err := reg.OpenForPurpose(ctx, receipt.UserID, storage.RenderProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	proxy := profile.Outbounds[0]
	if proxy.Username != "Test-User" || proxy.Password != string(secret) || proxy.Server != "entry.example" {
		t.Fatal("incorrect connection details")
	}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"client=sfa-1.14.4&ru_dm=1&ack=1", 422},
		{"client=sfa-1.15-alpha13&ru_dm=1", 422},
		{"client=sfa-1.15-alpha3", 422},
		{"client=sfa-1.14.4&client=sfa-1.15-alpha13", 400},
		{"client=sfa-1.14.4&password=forbidden", 400},
		{"client=sfa-1.15-alpha13", 200},
		{"client=sfa-1.15-alpha13&ru_dm=1&ack=1", 200},
	} {
		req := httptest.NewRequest("GET", "/api/v1/users/"+receipt.UserID+"/profiles/download?"+tc.query, nil)
		req.AddCookie(cookie)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != tc.status || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("option boundary", tc.query, resp.Code)
		}
		if tc.status != 200 && strings.Contains(resp.Body.String(), string(secret)) {
			t.Fatal("error disclosed credential")
		}
		if tc.status == 200 {
			var target, variant, hash string
			if err = db.QueryRow("SELECT target_client,routing_variant,profile_sha256 FROM profile_issuance ORDER BY id DESC LIMIT 1").Scan(&target, &variant, &hash); err != nil {
				t.Fatal(err)
			}
			if target != storage.ClientAlpha13 || hash != fmt.Sprintf("%x", sha256.Sum256(resp.Body.Bytes())) {
				t.Fatal("issuance metadata mismatch")
			}
			if strings.Contains(tc.query, "ru_dm=1") && variant != "ru_download_manager" || !strings.Contains(tc.query, "ru_dm=1") && variant != "base" {
				t.Fatal("wrong audited variant")
			}
		}
	}
	apiCall := func(method, path string, payload any, csrf, key string, want int) *httptest.ResponseRecorder {
		var body io.Reader
		if payload != nil {
			b, e := json.Marshal(payload)
			if e != nil {
				t.Fatal(e)
			}
			body = strings.NewReader(string(b))
		}
		req := httptest.NewRequest(method, path, body)
		req.AddCookie(cookie)
		req.Header.Set("Origin", auth.Origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Idempotency-Key", key)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != want || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("API boundary", method, path, resp.Code, want)
		}
		if strings.Contains(resp.Body.String(), string(secret)) {
			t.Fatal("metadata exposed VPN credential")
		}
		return resp
	}
	for _, path := range []string{"/api/v1/users", "/api/v1/users/" + receipt.UserID, "/api/v1/users/" + receipt.UserID + "/credential", "/api/v1/templates", "/api/v1/capabilities", "/api/v1/operations", "/api/v1/audits", "/api/v1/backups"} {
		apiCall("GET", path, nil, "", "", 200)
		req := httptest.NewRequest("GET", path, nil)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != 401 {
			t.Fatal("metadata unauthenticated", path, resp.Code)
		}
	}
	templates, e := reg.ApprovedTemplates(ctx)
	if e != nil || len(templates) == 0 {
		t.Fatal("templates", e)
	}
	createPayload := map[string]any{"login": "Case-API", "display_name": "Case API", "template_revision_id": templates[0].ID, "target_client": storage.Client1144}
	stable := "00000000-0000-4000-8000-000000000003"
	apiCall("POST", "/api/v1/users", createPayload, "", stable, 403)
	extractReceipt := func(resp *httptest.ResponseRecorder) string {
		var envelope struct {
			Data struct {
				OperationID string `json:"operation_id"`
				UserID      string `json:"user_id"`
			}
		}
		if json.Unmarshal(resp.Body.Bytes(), &envelope) != nil {
			t.Fatal("receipt JSON")
		}
		return envelope.Data.OperationID + "/" + envelope.Data.UserID
	}
	first := apiCall("POST", "/api/v1/users", createPayload, auth.CSRF(cookie.Value), stable, 202)
	replay := apiCall("POST", "/api/v1/users", createPayload, auth.CSRF(cookie.Value), stable, 202)
	if extractReceipt(first) != extractReceipt(replay) {
		t.Fatal("API replay changed receipt")
	}
	apiCall("POST", "/api/v1/users", createPayload, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000004", 409)
	createPayload["login"] = "case-api"
	apiCall("POST", "/api/v1/users", createPayload, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000005", 202)
	createPayload["password"] = "forbidden"
	apiCall("POST", "/api/v1/users", createPayload, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000006", 400)
	disable := map[string]any{"expected_version": 2, "reason": "owner test"}
	endpoint := "/api/v1/users/" + receipt.UserID
	apiCall("POST", endpoint+"/disable", disable, "wrong", "00000000-0000-4000-8000-000000000007", 403)
	apiCall("POST", endpoint+"/disable", map[string]any{"reason": "missing version"}, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000007", 428)
	response := apiCall("POST", endpoint+"/disable", disable, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000007", 202)
	var queued struct {
		Data struct {
			ID string `json:"operation_id"`
		}
	}
	if json.Unmarshal(response.Body.Bytes(), &queued) != nil || queued.Data.ID == "" {
		t.Fatal("missing mutation receipt")
	}
	apiCall("POST", endpoint+"/credential/rotate", disable, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000008", 409)
	apiCall("PATCH", endpoint, map[string]any{"expected_version": 2, "display_name": "blocked"}, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-000000000009", 409)
	if err = reg.Transition(ctx, queued.Data.ID, "queued", "cancelled"); err != nil {
		t.Fatal(err)
	}
	rename := map[string]any{"expected_version": 2, "display_name": "Renamed <exact>"}
	response = apiCall("PATCH", endpoint, rename, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-00000000000a", 202)
	replay = apiCall("PATCH", endpoint, rename, auth.CSRF(cookie.Value), "00000000-0000-4000-8000-00000000000a", 202)
	if extractReceipt(response) != extractReceipt(replay) {
		t.Fatal("rename replay changed receipt")
	}
	if json.Unmarshal(response.Body.Bytes(), &queued) != nil {
		t.Fatal("rename receipt")
	}
	apiCall("GET", "/api/v1/operations/"+queued.Data.ID, nil, "", "", 200)
	u, e := reg.GetUser(ctx, receipt.UserID)
	if e != nil || u.Login != "Test-User" || u.DisplayName != "Renamed <exact>" || u.Version != 3 {
		t.Fatal("rename changed immutable identity", e)
	}
	execSQL("UPDATE admin_sessions SET revoked_at=CURRENT_TIMESTAMP")
	fetch("GET", cookie, 401)
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM profile_issuance e JOIN admin_accounts a ON a.id=e.admin_id JOIN user_profiles p ON p.id=e.profile_id WHERE e.event='PROFILE_ISSUED' AND a.username='owner'`).Scan(&count); err != nil || count != 3 {
		t.Fatal("wrong issuance record", err)
	}
}
