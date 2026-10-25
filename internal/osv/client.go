package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultBaseURL is the public OSV API.
const DefaultBaseURL = "https://api.osv.dev"

// DefaultChunkSize is the OSV querybatch limit.
const DefaultChunkSize = 1000

// Client talks to the OSV API.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	ChunkSize int
}

// New returns a client for base (DefaultBaseURL if empty).
func New(base, version string) *Client {
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{
		BaseURL:   strings.TrimRight(base, "/"),
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		UserAgent: "crakit/" + version,
		ChunkSize: DefaultChunkSize,
	}
}

type batchQuery struct {
	Package   *batchPackage `json:"package,omitempty"`
	Version   string        `json:"version,omitempty"`
	PageToken string        `json:"page_token,omitempty"`
}

type batchPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Vuln is the subset of an OSV record crakit uses.
type Vuln struct {
	ID               string   `json:"id"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Aliases          []string `json:"aliases"`
	Severity         []Score  `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Severity string `json:"severity"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// Score is an OSV severity entry (type + vector string).
type Score struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("OSV %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(string(data), 200))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func queryFor(p Package) batchQuery {
	if p.PURL != "" {
		// A versioned purl carries the version; never send both (OSV rejects it).
		return batchQuery{Package: &batchPackage{PURL: p.PURL}}
	}
	return batchQuery{Package: &batchPackage{Name: p.Name, Ecosystem: p.Ecosystem}, Version: p.Version}
}

// QueryBatch returns the vulnerability IDs per package index, chunked at
// ChunkSize and following next_page_token per result.
func (c *Client) QueryBatch(ctx context.Context, pkgs []Package) ([][]string, error) {
	out := make([][]string, len(pkgs))
	size := c.ChunkSize
	if size <= 0 {
		size = DefaultChunkSize
	}
	for start := 0; start < len(pkgs); start += size {
		end := min(start+size, len(pkgs))
		pending := make([]int, 0, end-start)
		queries := make([]batchQuery, 0, end-start)
		for i := start; i < end; i++ {
			pending = append(pending, i)
			queries = append(queries, queryFor(pkgs[i]))
		}
		for len(queries) > 0 {
			data, err := c.do(ctx, http.MethodPost, "/v1/querybatch", map[string]any{"queries": queries})
			if err != nil {
				return nil, err
			}
			var br batchResponse
			if err := json.Unmarshal(data, &br); err != nil {
				return nil, fmt.Errorf("decode querybatch: %w", err)
			}
			if len(br.Results) != len(queries) {
				return nil, fmt.Errorf("querybatch returned %d results for %d queries", len(br.Results), len(queries))
			}
			var nextPending []int
			var nextQueries []batchQuery
			for i, r := range br.Results {
				idx := pending[i]
				for _, v := range r.Vulns {
					out[idx] = append(out[idx], v.ID)
				}
				if r.NextPageToken != "" {
					q := queries[i]
					q.PageToken = r.NextPageToken
					nextPending = append(nextPending, idx)
					nextQueries = append(nextQueries, q)
				}
			}
			pending, queries = nextPending, nextQueries
		}
	}
	return out, nil
}

// GetVuln fetches a single OSV record.
func (c *Client) GetVuln(ctx context.Context, id string) (*Vuln, error) {
	data, err := c.do(ctx, http.MethodGet, "/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode vuln %s: %w", id, err)
	}
	return &v, nil
}

// Finding is one vulnerability affecting one component.
type Finding struct {
	Component string   `json:"component"`
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Severity  Severity `json:"severity"`
	CVSS      string   `json:"cvss,omitempty"`
	FixedIn   []string `json:"fixed_in"`
	Summary   string   `json:"summary"`
}

// Scan queries all packages and resolves each vulnerability's details.
// Results are sorted by component then ID for stable output.
func (c *Client) Scan(ctx context.Context, pkgs []Package) ([]Finding, error) {
	ids, err := c.QueryBatch(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	cache := map[string]*Vuln{}
	var findings []Finding
	for i, list := range ids {
		for _, id := range list {
			v, ok := cache[id]
			if !ok {
				v, err = c.GetVuln(ctx, id)
				if err != nil {
					return nil, err
				}
				cache[id] = v
			}
			findings = append(findings, FindingFor(pkgs[i], v))
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Component != findings[j].Component {
			return findings[i].Component < findings[j].Component
		}
		return findings[i].ID < findings[j].ID
	})
	return findings, nil
}

// FindingFor builds a finding from a package and its OSV record.
func FindingFor(p Package, v *Vuln) Finding {
	f := Finding{Component: p.Label(), ID: v.ID, Aliases: v.Aliases, Summary: v.Summary}
	if f.Summary == "" {
		f.Summary = firstLine(v.Details)
	}
	f.Severity, f.CVSS = SeverityOf(v)
	seen := map[string]bool{}
	for _, a := range v.Affected {
		if p.PURL != "" && a.Package.PURL != "" && !samePackage(p.PURL, a.Package.PURL) {
			continue
		}
		if p.PURL == "" && a.Package.Name != "" && !strings.EqualFold(a.Package.Name, p.Name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					f.FixedIn = append(f.FixedIn, e.Fixed)
				}
			}
		}
	}
	return f
}

func samePackage(a, b string) bool {
	strip := func(s string) string {
		if i := strings.LastIndex(s, "@"); i > 0 {
			s = s[:i]
		}
		if i := strings.Index(s, "?"); i > 0 {
			s = s[:i]
		}
		return strings.ToLower(s)
	}
	return strip(a) == strip(b)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return truncate(s, 120)
}
