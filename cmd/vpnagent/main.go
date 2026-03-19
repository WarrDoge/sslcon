//go:build linux || darwin || windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/service"
	"sslcon/base"
	"sslcon/rpc"
	"sslcon/svc"
)

func main() {
	if len(os.Args) < 2 {
		if service.Interactive() {
			base.Setup()
			rpc.Setup()
			watchSignal()
		} else {
			svc.RunSvc()
		}
	} else {
		cmd := os.Args[1]
		switch cmd {
		case "install":
			svc.InstallSvc()
		case "uninstall":
			svc.UninstallSvc()
			// TODO: uninstall wintun driver
		default:
			fmt.Println("invalid command: ", cmd)
		}
	}
}

func watchSignal() {
	base.Info("Server pid: ", os.Getpid())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	for {
		sig := <-sigs
		base.Info("Get signal:", sig)
		switch sig {
		default:
			base.Info("Stop")
			rpc.DisConnect()
			return
		}
	}
}
