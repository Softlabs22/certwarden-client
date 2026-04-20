package main

import (
	"certwarden-client/pkg/app"
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/logger"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
)

const ProgramName = "certwarden-client"

var (
	Version   = "unknown"
	BuildDate = "No idea"
)

func main() {
	parser := argparse.NewParser(os.Args[0], "A simple CertWarden client")
	configPath := parser.String("c", "config", &argparse.Options{Required: false, Help: "Configuration file path"})
	version := parser.Flag("v", "version", &argparse.Options{Required: false, Help: "Show program version"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}
	if *version {
		fmt.Printf("%s version: %s, build date: %s\n", ProgramName, Version, BuildDate)
		os.Exit(0)
	}
	conf := config.Config{}
	err = conf.Load(*configPath)
	if err != nil {
		fmt.Printf("Cannot load config: %s\n", err)
		os.Exit(1)
	}

	err = logger.SetupLogging(&conf)
	if err != nil {
		fmt.Printf("Cannot setup logging: %s\n", err)
		os.Exit(1)
	}

	err = app.Run(&conf)
	if err != nil {
		logger.Log.Fatal(err)
	}
	logger.Log.Exit(0)
}
