package caddy

// ApplyNotice is shared by the CLI and future operation previews in the UI.
// It describes the measured G0b strategy without promising seamless changes
// or implying that revocation terminates already established tunnels.
const ApplyNotice = "Apply mode: verified Unix reload; uninterrupted service is not guaranteed. Revocation blocks new connections; existing tunnels may stay open. A service restart interrupts VPN connections and requires separate approval."
