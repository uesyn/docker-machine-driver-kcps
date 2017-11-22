package main

import (
	kcps "github.com/uesyn/docker-machine-driver-kcps"

	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(kcps.NewDriver("", ""))
}
