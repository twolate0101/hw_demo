package fingerprint

import (
	"strings"

	"github.com/twolate0101/hw_demo/internal/model"
)

type ruleEngine struct {
	rules []Rule
}

// NewEngine loads and validates all fingerprints up front. A server should not
// become healthy if this function returns an error.
func NewEngine(rulesPath string) (Engine, error) {
	rules, err := loadRules(rulesPath)
	if err != nil {
		return nil, err
	}
	return &ruleEngine{rules: rules}, nil
}

func (e *ruleEngine) Identify(in model.ScanInput) model.FingerprintResult {
	out := model.FingerprintResult{IP: in.IP, Port: in.Port, Protocol: "unknown"}
	banner := in.Banner

	if version, ok := mysqlVersion([]byte(banner)); ok {
		out.Protocol = "MySQL"
		out.Product = "MySQL"
		out.Version = version
		out.Confidence = 0.95
		return out
	}

	for _, rule := range e.rules {
		matches := rule.re.FindStringSubmatch(banner)
		if matches == nil {
			continue
		}
		out.Protocol = rule.Protocol
		out.Product = rule.Product
		out.Confidence = rule.Confidence
		if rule.VersionGroup > 0 {
			out.Version = strings.TrimSpace(matches[rule.VersionGroup])
		}
		if rule.OSGroup > 0 {
			out.OSHint = normalizeOS(matches[rule.OSGroup])
		} else if rule.OSHint != "" {
			out.OSHint = rule.OSHint
		}
		if out.OSHint == "" {
			out.OSHint = inferOS(banner)
		}
		return out
	}
	return out
}

// mysqlVersion recognizes protocol-v10 initial handshakes. It verifies the
// three-byte packet length, sequence id and NUL-terminated server version.
func mysqlVersion(b []byte) (string, bool) {
	if len(b) < 6 {
		return "", false
	}
	packetLen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if b[3] != 0 || b[4] != 0x0a || packetLen < 2 {
		return "", false
	}
	payload := b[5:]
	end := strings.IndexByte(string(payload), 0)
	if end <= 0 || end > 100 {
		return "", false
	}
	version := string(payload[:end])
	for _, c := range version {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return version, true
}

func inferOS(s string) string {
	lower := strings.ToLower(s)
	for _, candidate := range []struct{ needle, name string }{
		{"ubuntu", "Ubuntu"},
		{"debian", "Debian"},
		{"centos", "CentOS"},
		{"red hat", "Red Hat"},
		{"rhel", "Red Hat"},
		{"freebsd", "FreeBSD"},
		{"win32", "Windows"},
		{"windows", "Windows"},
	} {
		if strings.Contains(lower, candidate.needle) {
			return candidate.name
		}
	}
	return ""
}

func normalizeOS(s string) string {
	if inferred := inferOS(s); inferred != "" {
		return inferred
	}
	return strings.Trim(strings.TrimSpace(s), "()")
}
