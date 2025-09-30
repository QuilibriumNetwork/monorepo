package aliases

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// AddressBytes encodes to YAML as a hex string.
type AddressBytes []byte

func (a AddressBytes) MarshalYAML() (any, error) {
	return fmt.Sprintf("%x", []byte(a)), nil
}

func (a *AddressBytes) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.Wrap(
			fmt.Errorf("address must be a scalar"),
			"unmarshal yaml",
		)
	}
	b, err := parseAddressLiteral(node.Value)
	if err != nil {
		return err
	}
	*a = AddressBytes(b)
	return nil
}

type Alias struct {
	Address AddressBytes `yaml:"address"`
	Type    string       `yaml:"type,omitempty"`
}

func (a *Alias) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var addr AddressBytes
		if err := node.Decode(&addr); err != nil {
			return err
		}
		*a = Alias{Address: addr}
		return nil
	case yaml.MappingNode:
		type alias Alias
		var tmp alias
		if err := node.Decode(&tmp); err != nil {
			return err
		}
		*a = Alias(tmp)
		return nil
	default:
		return errors.Wrap(
			fmt.Errorf("alias must be a scalar or mapping"),
			"unmarshal yaml",
		)
	}
}

type File struct {
	Aliases map[string]Alias `yaml:"aliases"`
}

// Store keeps aliases in memory and persists to disk.
type Store struct {
	mu   sync.Mutex
	data File
	path string // file path for autosave
}

// NewInMemory creates an empty store without a path (no autosave).
func NewInMemory() *Store {
	return &Store{data: File{Aliases: map[string]Alias{}}}
}

// NewOnDisk creates (or loads) a file-backed store with no aliases yet.
func NewOnDisk(path string) (*Store, error) {
	// Try to load if present
	if st, err := Load(path); err == nil {
		return st, nil
	} else if !os.IsNotExist(err) {
		return nil, errors.Wrap(err, "new on disk")
	}

	// Not found
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	s := &Store{data: File{Aliases: map[string]Alias{}}, path: path}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads from path and returns a file-backed store (autosave enabled).
func Load(path string) (*Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadFromReader(path, f)
}

// LoadFromReader reads a store from r; if path != "" autosave is enabled.
func LoadFromReader(path string, r io.Reader) (*Store, error) {
	var file File
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	if file.Aliases == nil {
		file.Aliases = make(map[string]Alias)
	}
	return &Store{data: file, path: path}, nil
}

// Save writes the store to its path (or to provided path if non-empty).
func (s *Store) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path != "" {
		s.path = path
	}
	return s.saveLocked()
}

// Put inserts or replaces an alias and autosaves.
func (s *Store) Put(name string, addr []byte, typeHint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Aliases == nil {
		s.data.Aliases = make(map[string]Alias)
	}
	s.data.Aliases[name] = Alias{
		Address: AddressBytes(append([]byte(nil), addr...)),
		Type:    typeHint,
	}
	return s.saveLocked()
}

// Remove deletes an alias (if present) and autosaves when a deletion happens.
// Returns (deleted, error).
func (s *Store) Delete(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Aliases[name]; !ok {
		return false, nil
	}
	delete(s.data.Aliases, name)
	return true, s.saveLocked()
}

// List returns sorted alias names.
func (s *Store) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.data.Aliases))
	for k := range s.data.Aliases {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get returns (addr, type, ok).
func (s *Store) Get(name string) ([]byte, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	al, ok := s.data.Aliases[name]
	if !ok {
		return nil, "", false
	}
	return append([]byte(nil), al.Address...), al.Type, true
}

// FindByAddress returns (name, type, ok) for exact byte match.
func (s *Store) FindByAddress(addr []byte) (string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.data.Aliases {
		if bytesEqual(v.Address, addr) {
			return k, v.Type, true
		}
	}
	return "", "", false
}

// Resolve: alias name -> (addr, type), else parse literal hex -> (addr, "")
func (s *Store) Resolve(key string) ([]byte, string, bool) {
	if addr, typ, ok := s.Get(key); ok {
		return addr, typ, true
	}
	if b, err := parseAddressLiteral(key); err == nil {
		return b, "", true
	}
	return nil, "", false
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return errors.New(
			"no path set for autosave; call Save(path) once or use NewOnDisk/Load",
		)
	}
	tmp := s.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(&s.data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := enc.Close(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseAddressLiteral(s string) ([]byte, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return nil, errors.New("empty address")
	}

	return hex.DecodeString(t)
}
