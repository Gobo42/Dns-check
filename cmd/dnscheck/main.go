package main

import (
	"fmt"
	"os"

	"dnscheck/internal/app"
)

func main() {
	if err := app.Main(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
