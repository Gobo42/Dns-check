package blocklist

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Rule struct {
	LineNumber int    `json:"line_number"`
	Text       string `json:"text"`
}

type ParseError struct {
	LineNumber int    `json:"line_number"`
	Text       string `json:"text"`
	Reason     string `json:"reason"`
}

type List struct {
	Rules  []Rule       `json:"rules"`
	Errors []ParseError `json:"errors,omitempty"`
}

type Loaded struct {
	List      List
	Source    string
	Local     bool
	LocalPath string
}

func Parse(r io.Reader) (List, error) {
	scanner := bufio.NewScanner(r)
	var rules []Rule
	var parseErrors []ParseError
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if reason := invalidRuleReason(text); reason != "" {
			parseErrors = append(parseErrors, ParseError{LineNumber: lineNo, Text: text, Reason: reason})
			continue
		}
		rules = append(rules, Rule{
			LineNumber: lineNo,
			Text:       strings.ToLower(strings.TrimSuffix(text, ".")),
		})
	}
	if err := scanner.Err(); err != nil {
		return List{}, err
	}
	return List{Rules: rules, Errors: parseErrors}, nil
}

func LoadSource(source string, insecureSkipTLSVerify bool) (Loaded, error) {
	loaded := Loaded{Source: source}
	var reader io.Reader

	if isHTTPSource(source) {
		client := newHTTPClient(insecureSkipTLSVerify)
		resp, err := client.Get(source)
		if err != nil {
			return Loaded{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return Loaded{}, fmt.Errorf("blocklist fetch status %s", resp.Status)
		}
		reader = resp.Body
	} else {
		localPath, err := expandHome(source)
		if err != nil {
			return Loaded{}, err
		}
		file, err := os.Open(localPath)
		if err != nil {
			return Loaded{}, err
		}
		defer file.Close()
		reader = file
		loaded.Local = true
		loaded.LocalPath = localPath
	}

	list, err := Parse(reader)
	if err != nil {
		return Loaded{}, err
	}
	loaded.List = list
	return loaded, nil
}

func newHTTPClient(insecureSkipTLSVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify},
		},
	}
}

func (l List) Match(host string) []Rule {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var matches []Rule
	for _, rule := range l.Rules {
		if ruleMatches(rule.Text, host) {
			matches = append(matches, rule)
		}
	}
	return matches
}

func SedDeleteCommand(path string, rule Rule) string {
	return fmt.Sprintf("sed -i '/^%s$/d' %s", sedRegexEscape(rule.Text), shellQuote(path))
}

func isHTTPSource(source string) bool {
	lower := strings.ToLower(source)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func invalidRuleReason(text string) string {
	if strings.ContainsAny(text, " \t\r\n") {
		return "contains whitespace"
	}
	if strings.Contains(text, "://") || strings.ContainsAny(text, `/\:`) {
		return "contains URL or path syntax"
	}
	trimmed := strings.TrimSuffix(strings.ToLower(text), ".")
	if trimmed == "" || strings.HasPrefix(trimmed, ".") || strings.Contains(trimmed, "..") {
		return "contains empty DNS label"
	}
	for _, ch := range trimmed {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '*' {
			continue
		}
		return fmt.Sprintf("contains unsupported character %q", ch)
	}
	return ""
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return home + path[1:], nil
}

func ruleMatches(pattern, host string) bool {
	switch {
	case strings.HasPrefix(pattern, "*."):
		suffix := strings.TrimPrefix(pattern, "*.")
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	case strings.Contains(pattern, "*"):
		re := "^" + regexp.QuoteMeta(pattern) + "$"
		re = strings.ReplaceAll(re, `\*`, `[^.]+`)
		return regexp.MustCompile(re).MatchString(host)
	default:
		return host == pattern || strings.HasSuffix(host, "."+pattern)
	}
}

func sedRegexEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`*`, `\*`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`$`, `\$`,
		`/`, `\/`,
	)
	return replacer.Replace(s)
}

func shellQuote(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}();&|<>") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
