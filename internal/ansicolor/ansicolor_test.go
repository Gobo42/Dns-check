package ansicolor

import "testing"

func TestColorWrapsWhenEnabled(t *testing.T) {
	got := Color("host.example", "purple", true)
	want := "\x1b[35mhost.example\x1b[0m"
	if got != want {
		t.Fatalf("Color = %q, want %q", got, want)
	}
}

func TestColorNoOpWhenDisabled(t *testing.T) {
	got := Color("host.example", "purple", false)
	if got != "host.example" {
		t.Fatalf("Color = %q, want unchanged string", got)
	}
}

func TestColorUnknownNameReturnsUnchanged(t *testing.T) {
	got := Color("host.example", "not-a-color", true)
	if got != "host.example" {
		t.Fatalf("Color = %q, want unchanged string for unknown color name", got)
	}
}

func TestAllExpectedColorsAreRegistered(t *testing.T) {
	for _, name := range []string{"red", "green", "yellow", "blue", "purple"} {
		if got := Color("x", name, true); got == "x" {
			t.Errorf("color %q is not registered", name)
		}
	}
}
