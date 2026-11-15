package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func authWhoami(out, stderr io.Writer) int {
	cookie, e := ownerCookie()
	if e != nil {
		fmt.Fprintln(stderr, "Private owner session unavailable")
		return 3
	}
	socket := os.Getenv("VPNCTL_SOCKET")
	if socket == "" {
		socket = "/run/vpn-control/api.sock"
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	req, e := http.NewRequest("GET", "http://localhost/api/v1/auth/me", nil)
	if e != nil {
		return 2
	}
	req.AddCookie(&cookie)
	resp, e := client.Do(req)
	if e != nil {
		fmt.Fprintln(stderr, "Owner identity unavailable")
		return 5
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintln(stderr, "Owner identity refused:", resp.StatusCode)
		return 3
	}
	var envelope struct {
		Data struct {
			Username  string `json:"username"`
			Role      string `json:"role"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&envelope); e != nil || envelope.Data.Username == "" || envelope.Data.Role != "owner" || envelope.Data.ExpiresAt == "" {
		fmt.Fprintln(stderr, "Invalid owner identity response")
		return 5
	}
	if e = json.NewEncoder(out).Encode(envelope.Data); e != nil {
		return 9
	}
	return 0
}
