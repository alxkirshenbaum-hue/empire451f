#!/bin/bash
set -eu
code=$(curl -fsSL --proto '=https' https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.3/bootstrap/macos.sh)
exec /bin/bash -c "$code"
