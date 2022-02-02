package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "minijks",
		Version: "1.1.0",
		Usage:   "inspect, unpack and pack Java keystore files",
		Commands: []*cli.Command{
			InspectCommand,
			UnpackCommand,
			PackCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
