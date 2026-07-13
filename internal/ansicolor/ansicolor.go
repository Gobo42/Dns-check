// Package ansicolor holds the ANSI color codes shared by dnscheck's
// human-readable report and verbose debug logging, so every package colors
// the same category of value (hostnames, addresses, booleans, ...) the same
// way.
package ansicolor

var codes = map[string]string{
	"red":    "31",
	"green":  "32",
	"yellow": "33",
	"blue":   "34",
	"purple": "35",
}

// Color wraps s in the ANSI escape code for name when enabled is true.
// An unrecognized name or enabled=false returns s unchanged.
func Color(s, name string, enabled bool) string {
	if !enabled {
		return s
	}
	code, ok := codes[name]
	if !ok {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
