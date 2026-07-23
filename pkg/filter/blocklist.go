package filter

import (
	"sync"
)

// BlocklistFilter provides fast, exact HASSH lookup.
//
// A single RWMutex-guarded map.
type BlocklistFilter struct {
	mu    sync.RWMutex
	exact map[string]bool
}

// NewBlocklistFilter creates an empty blocklist.
func NewBlocklistFilter() *BlocklistFilter {
	return &BlocklistFilter{
		exact: make(map[string]bool),
	}
}

// Add inserts a HASSH fingerprint into the blocklist
func (b *BlocklistFilter) Add(hassh string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.exact[hassh] = true
}

// Contains checks if a HASSH is blocked
func (b *BlocklistFilter) Contains(hassh string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.exact[hassh]
}

// Reload replaces the blocklist contents with new data
func (b *BlocklistFilter) Reload(blockedHashes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.exact = make(map[string]bool, len(blockedHashes))
	for _, hassh := range blockedHashes {
		b.exact[hassh] = true
	}
}

// Count returns the number of blocked hashes
func (b *BlocklistFilter) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact)
}
