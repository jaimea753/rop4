// Package cache is the on-disk gadget cache (ported from rop3/cache.py). The
// SHA-256 key binds the file-content hash and every result-affecting option, so
// a changed file or option misses cleanly.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Version is bumped when the on-disk record format changes (invalidating old
// entries). Matches rop3 CACHE_VERSION.
const Version = 2

// DefaultDir returns $XDG_CACHE_HOME/rop4 (or ~/.cache/rop4).
func DefaultDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "rop4")
}

// Record is one cached gadget: [vaddr, hexBytes, frame]. Frame is nil when the
// scan produced no framing mask.
type Record struct {
	Vaddr uint64
	Hex   string
	Frame []bool // nil = no mask
}

// Cache stores gadget records under a directory.
type Cache struct {
	Dir string
}

// New builds a cache rooted at dir (empty -> DefaultDir).
func New(dir string) *Cache {
	if dir == "" {
		dir = DefaultDir()
	}
	return &Cache{Dir: dir}
}

// FileHash is the SHA-256 of the binary contents.
func FileHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Key hashes {version, hash, params} with sorted keys (matches rop3 key()).
func (c *Cache) Key(fileHash string, params map[string]any) (string, error) {
	material, err := json.Marshal(map[string]any{
		"version": Version,
		"hash":    fileHash,
		"params":  params,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Cache) path(key string) string { return filepath.Join(c.Dir, key+".json") }

// recordWire is the JSON shape: an array per record, matching rop3
// ([vaddr, hex] or [vaddr, hex, frame]).
type recordWire []json.RawMessage

// Load returns the cached records, or (nil,false) on a miss.
func (c *Cache) Load(key string) ([]Record, bool) {
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}
	var raw []recordWire
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false
	}
	out := make([]Record, 0, len(raw))
	for _, r := range raw {
		if len(r) < 2 {
			return nil, false
		}
		var rec Record
		if err := json.Unmarshal(r[0], &rec.Vaddr); err != nil {
			return nil, false
		}
		if err := json.Unmarshal(r[1], &rec.Hex); err != nil {
			return nil, false
		}
		if len(r) > 2 {
			// frame may be null or a bool array.
			var frame []bool
			if err := json.Unmarshal(r[2], &frame); err == nil {
				rec.Frame = frame
			}
		}
		out = append(out, rec)
	}
	return out, true
}

// Store persists records atomically; failures are non-fatal (returns the error
// for the caller to log as a warning, matching rop3's behavior).
func (c *Cache) Store(key string, records []Record) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	wire := make([]recordWire, 0, len(records))
	for _, rec := range records {
		vb, _ := json.Marshal(rec.Vaddr)
		hb, _ := json.Marshal(rec.Hex)
		item := recordWire{vb, hb}
		if rec.Frame != nil {
			fb, _ := json.Marshal(rec.Frame)
			item = append(item, fb)
		} else {
			item = append(item, json.RawMessage("null"))
		}
		wire = append(wire, item)
	}
	blob, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, "*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, c.path(key)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("could not write gadget cache: %w", err)
	}
	return nil
}
