//go:build !linux

package main

import "time"

func collectLocalResources(out *localResources, directory string, now time.Time) {}
