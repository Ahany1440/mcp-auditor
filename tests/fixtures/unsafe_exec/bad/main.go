package main

import "os/exec"

func run(host string) {
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
