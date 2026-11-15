package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func authPasswd(stderr io.Writer) int {
	cookie, e := ownerCookie()
	if e != nil {
		fmt.Fprintln(stderr, "Private owner session unavailable")
		return 3
	}
	prompts := []string{"Current panel owner password:", "New panel owner password:", "Repeat new panel owner password:"}
	values := make([]string, 3)
	for i, prompt := range prompts {
		raw, e := exec.Command("systemd-ask-password", prompt).Output()
		if e != nil {
			clear(raw)
			return 3
		}
		if len(raw) > 1025 {
			clear(raw)
			return 2
		}
		values[i] = strings.TrimSuffix(string(raw), "\n")
		clear(raw)
	}
	if len(values[1]) < 12 || len(values[1]) > 1024 || values[1] != values[2] {
		fmt.Fprintln(stderr, "New passwords must match and contain 12 to 1024 bytes")
		return 2
	}
	data, e := json.Marshal(map[string]string{"old_password": values[0], "new_password": values[1], "confirm_password": values[2]})
	clear(values)
	if e != nil {
		return 2
	}
	defer clear(data)
	socket := os.Getenv("VPNCTL_SOCKET")
	if socket == "" {
		socket = "/run/vpn-control/api.sock"
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	response, e := postAuth(client, "change-password", bytes.NewReader(data), cookie.Value)
	if e != nil {
		fmt.Fprintln(stderr, "Password change outcome unknown; try signing in again before retrying")
		return 5
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		fmt.Fprintln(stderr, "Password change refused:", response.StatusCode)
		return 3
	}
	if e = os.Remove(os.Getenv("VPNCTL_SESSION_FILE")); e != nil {
		fmt.Fprintln(stderr, "Password changed; remove the obsolete local session file")
		return 9
	}
	fmt.Fprintln(stderr, "Password changed. All owner sessions revoked; sign in again.")
	return 0
}
