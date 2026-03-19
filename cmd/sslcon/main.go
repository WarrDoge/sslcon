//go:build linux || darwin || windows

package main

import "github.com/WarrDoge/sslcon/cmd"

func main() {
	cmd.Execute()
}
