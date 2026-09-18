package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// Rule is the external, data-driven form of a banner fingerprint.
type Rule struct {
	Name         string  `json:"name"`
	Priority     int     `json:"priority"`
	Pattern      string  `json:"pattern"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product,omitempty"`
	VersionGroup int     `json:"version_group,omitempty"`
	OSGroup      int     `json:"os_group,omitempty"`
	OSHint       string  `json:"os_hint,omitempty"`
	Confidence   float64 `json:"confidence"`

	re *regexp.Regexp
}

type ruleFile struct {
	Rules []Rule `json:"rules"`
}

func loadRules(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}

	var f ruleFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("rules file contains no rules")
	}

	seen := make(map[string]struct{}, len(f.Rules))
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.Name == "" || r.Pattern == "" || r.Protocol == "" {
			return nil, fmt.Errorf("rule %d: name, pattern and protocol are required", i)
		}
		if _, ok := seen[r.Name]; ok {
			return nil, fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = struct{}{}
		if r.Confidence < 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("rule %q: confidence must be between 0 and 1", r.Name)
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: compile pattern: %w", r.Name, err)
		}
		groups := r.re.NumSubexp()
		if r.VersionGroup < 0 || r.VersionGroup > groups || r.OSGroup < 0 || r.OSGroup > groups {
			return nil, fmt.Errorf("rule %q: capture group is out of range", r.Name)
		}
	}

	sort.SliceStable(f.Rules, func(i, j int) bool {
		return f.Rules[i].Priority > f.Rules[j].Priority
	})
	return f.Rules, nil
}
