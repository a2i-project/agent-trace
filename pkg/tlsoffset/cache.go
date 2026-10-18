package tlsoffset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Cache manages the persistence of validated SSL_write offsets.
type Cache struct {
	path string
	mu   sync.RWMutex
}

// NewCache returns a Cache backed by the given JSON file path.
func NewCache(path string) *Cache {
	return &Cache{path: path}
}

// Lookup returns the cached Target for a given build ID, or nil if not found.
func (c *Cache) Lookup(buildID string) *Target {
	if buildID == "" {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil
	}

	var targets map[string]Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil
	}

	if t, ok := targets[buildID]; ok {
		return &t
	}
	return nil
}

// Store saves a validated Target to the cache for its build ID.
func (c *Cache) Store(buildID string, target Target) error {
	if buildID == "" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	targets := make(map[string]Target)

	// Read existing targets so we don't overwrite others
	if data, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(data, &targets)
	}

	targets[buildID] = target

	// Ensure directory exists
	if dir := filepath.Dir(c.path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically-ish by writing to temp then renaming
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
