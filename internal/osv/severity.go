package osv

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Severity is a qualitative rating.
type Severity string

const (
	SevUnknown  Severity = "unknown"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank orders severities; unknown is lowest.
func (s Severity) Rank() int {
	switch s {
	case SevLow:
		return 1
	case SevMedium:
		return 2
	case SevHigh:
		return 3
	case SevCritical:
		return 4
	}
	return 0
}

// ParseSeverity parses a user-supplied severity name.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "":
		return "", nil
	case "low":
		return SevLow, nil
	case "medium", "moderate":
		return SevMedium, nil
	case "high":
		return SevHigh, nil
	case "critical":
		return SevCritical, nil
	}
	return "", fmt.Errorf("unknown severity %q (want none, low, medium, high or critical)", s)
}

// SeverityOf derives a qualitative severity for a record. Priority:
// database_specific.severity, affected[].ecosystem_specific.severity, then a
// CVSS v3.x base score computed from the vector in severity[]. The CVSS
// vector used (if any) is returned too.
func SeverityOf(v *Vuln) (Severity, string) {
	vector := ""
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			vector = s.Score
			if s.Type == "CVSS_V3" {
				break
			}
		}
	}
	if s, err := ParseSeverity(v.DatabaseSpecific.Severity); err == nil && s != "" {
		return s, vector
	}
	for _, a := range v.Affected {
		if s, err := ParseSeverity(a.EcosystemSpecific.Severity); err == nil && s != "" {
			return s, vector
		}
	}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, ok := CVSS3BaseScore(s.Score); ok {
				return FromScore(score), s.Score
			}
		}
	}
	return SevUnknown, vector
}

// FromScore maps a CVSS base score to the qualitative scale.
func FromScore(score float64) Severity {
	switch {
	case score == 0:
		return SevUnknown
	case score < 4.0:
		return SevLow
	case score < 7.0:
		return SevMedium
	case score < 9.0:
		return SevHigh
	}
	return SevCritical
}

// CVSS3BaseScore computes the base score of a CVSS v3.0/v3.1 vector string.
func CVSS3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scopeChanged {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scopeChanged {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, cok := cia[m["C"]]
	i, iok := cia[m["I"]]
	a, aok := cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !cok || !iok || !aok {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	var base float64
	if scopeChanged {
		base = roundUp(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp(math.Min(impact+exploitability, 10))
	}
	return base, true
}

// roundUp implements the CVSS v3.1 Roundup function.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// ExitCode returns 1 if any finding has severity at or above threshold,
// 0 otherwise. An empty threshold ("none") never fails. Unknown severities
// only trigger when the threshold is unknown/empty-rank, which it never is.
func ExitCode(findings []Finding, threshold Severity) int {
	if threshold == "" {
		return 0
	}
	for _, f := range findings {
		if f.Severity.Rank() >= threshold.Rank() && f.Severity != SevUnknown {
			return 1
		}
	}
	return 0
}

// FormatScore renders a float score compactly.
func FormatScore(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}
