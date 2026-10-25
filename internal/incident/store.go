package incident

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStorePath resolves $CRAKIT_STORE, else
// $XDG_CONFIG_HOME/crakit/incidents.json (XDG default ~/.config).
func DefaultStorePath() string {
	if p := os.Getenv("CRAKIT_STORE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "crakit", "incidents.json")
}

// Store is a JSON file of incidents.
type Store struct {
	Path      string
	Incidents []*Incident `json:"incidents"`
}

// Load reads the store; a missing file yields an empty store.
func Load(path string) (*Store, error) {
	s := &Store{Path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.Path = path
	return s, nil
}

// Save writes the store atomically with owner-only permissions.
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Add appends an incident.
func (s *Store) Add(in *Incident) {
	s.Incidents = append(s.Incidents, in)
}

// Get finds an incident by id or unique id prefix.
func (s *Store) Get(id string) (*Incident, error) {
	var match *Incident
	for _, in := range s.Incidents {
		if in.ID == id {
			return in, nil
		}
		if len(id) >= 2 && len(in.ID) > len(id) && in.ID[:len(id)] == id {
			if match != nil {
				return nil, fmt.Errorf("ambiguous id prefix %q", id)
			}
			match = in
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no incident with id %q", id)
	}
	return match, nil
}
