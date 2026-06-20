package blocklist

import (
	"strings"
	"testing"
)

func TestParsePreservesLineNumbersAndIgnoresComments(t *testing.T) {
	list, err := Parse(strings.NewReader("######## header ########\n# comment\nad.*\n\n*.nr-data.net\nactivate.adobe.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(list.Rules))
	}
	if list.Rules[0].LineNumber != 3 || list.Rules[0].Text != "ad.*" {
		t.Fatalf("first rule = %#v", list.Rules[0])
	}
	if list.Rules[1].LineNumber != 5 || list.Rules[1].Text != "*.nr-data.net" {
		t.Fatalf("second rule = %#v", list.Rules[1])
	}
}

func TestParseSkipsInvalidLinesAndReportsLineText(t *testing.T) {
	list, err := Parse(strings.NewReader("good.example\nbad entry with spaces\nhttps://bad.example/path\n*.also-good.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(list.Rules))
	}
	if len(list.Errors) != 2 {
		t.Fatalf("parse errors = %d, want 2: %#v", len(list.Errors), list.Errors)
	}
	if list.Errors[0].LineNumber != 2 || list.Errors[0].Text != "bad entry with spaces" {
		t.Fatalf("first parse error = %#v", list.Errors[0])
	}
	if list.Errors[1].LineNumber != 3 || list.Errors[1].Text != "https://bad.example/path" {
		t.Fatalf("second parse error = %#v", list.Errors[1])
	}
	if got := list.Match("also-good.example"); len(got) != 1 {
		t.Fatalf("valid line after errors did not parse: %#v", got)
	}
}

func TestMatchExactLeadingWildcardAndLabelWildcard(t *testing.T) {
	list, err := Parse(strings.NewReader("ad.*\n*.nr-data.net\nactivate.adobe.com\nmmstat.com\npinterest.net\n"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"ad.example":              "ad.*",
		"bam.nr-data.net":         "*.nr-data.net",
		"deep.bam.nr-data.net":    "*.nr-data.net",
		"activate.adobe.com":      "activate.adobe.com",
		"sg.mmstat.com":           "mmstat.com",
		"www.gslb2.pinterest.net": "pinterest.net",
	}

	for host, want := range cases {
		matches := list.Match(host)
		if len(matches) == 0 {
			t.Fatalf("%s: expected match %s", host, want)
		}
		if matches[0].Text != want {
			t.Fatalf("%s: match = %q, want %q", host, matches[0].Text, want)
		}
	}
}

func TestSedDeleteCommandEscapesExactRule(t *testing.T) {
	rule := Rule{LineNumber: 8, Text: "*.events.launchdarkly.com"}
	got := SedDeleteCommand("/tmp/blocked-names.txt", rule)
	want := `sed -i '/^\*\.events\.launchdarkly\.com$/d' /tmp/blocked-names.txt`
	if got != want {
		t.Fatalf("sed command = %q, want %q", got, want)
	}
}
