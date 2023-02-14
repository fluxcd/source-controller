/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package index

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
)

// Digester is a simple string key value index that can be used to calculate
// digests of the index. The digests are cached, and only recalculated if the
// index has changed.
type Digester struct {
	// index is the map of keys and their associated values.
	index map[string]string

	// digests is a cache of digests calculated for the index.
	digests map[digest.Algorithm]digest.Digest

	mu sync.RWMutex
}

// DigesterOption is a functional option for configuring a digester.
type DigesterOption func(*Digester)

// WithIndex returns a DigesterOption that sets the index to the provided map.
// The map is copied, so any changes to the map after the option is applied
// will not be reflected in the index.
func WithIndex(i map[string]string) DigesterOption {
	return func(d *Digester) {
		if i != nil {
			d.mu.Lock()
			defer d.mu.Unlock()

			if d.index == nil {
				d.index = make(map[string]string, len(i))
			}
			for k, v := range i {
				d.index[k] = v
			}
			d.reset()
		}
	}
}

// NewDigester returns a new digest index with an empty initialized index.
func NewDigester(opts ...DigesterOption) *Digester {
	d := &Digester{
		digests: make(map[digest.Algorithm]digest.Digest, 0),
		index:   make(map[string]string, 0),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Add adds the key and digest to the index.
func (i *Digester) Add(key, value string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.index[key] = value
	i.reset()
}

// Delete removes the key from the index.
func (i *Digester) Delete(key string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if _, ok := i.index[key]; ok {
		delete(i.index, key)
		i.reset()
	}
}

// Get returns the digest for the key, or an empty digest if the key is not
// found.
func (i *Digester) Get(key string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.index[key]
}

// Has returns true if the index contains the key.
func (i *Digester) Has(key string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	_, ok := i.index[key]
	return ok
}

// Index returns a copy of the index.
func (i *Digester) Index() map[string]string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	index := make(map[string]string, len(i.index))
	for k, v := range i.index {
		index[k] = v
	}
	return index
}

// Len returns the number of keys in the index.
func (i *Digester) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.index)
}

// String returns a string representation of the index. The keys are stable
// sorted, and the string representation of the key/value pairs is written,
// each pair on a newline with a space between them.
func (i *Digester) String() string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	keys := i.sortedKeys()
	var b strings.Builder
	for _, k := range keys {
		b.Grow(len(k) + len(i.index[k]) + 2)
		writeLine(&b, k, i.index[k])
	}
	return b.String()
}

// WriteTo writes the index to the writer. The keys are stable sorted, and the
// string representation of the key/value pairs is written, each pair on a
// newline with a space between them.
func (i *Digester) WriteTo(w io.Writer) (int64, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	keys := i.sortedKeys()
	var n int64
	for _, k := range keys {
		nn, err := writeLine(w, k, i.index[k])
		n += int64(nn)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Digest returns the digest of the index using the provided algorithm.
// If the index has not changed since the last call to Digest, the cached
// digest is returned.
// For verifying the index against a known digest, use Verify.
func (i *Digester) Digest(a digest.Algorithm) digest.Digest {
	i.mu.Lock()
	defer i.mu.Unlock()

	if _, ok := i.digests[a]; !ok {
		digester := a.Digester()
		keys := i.sortedKeys()
		for _, k := range keys {
			_, _ = writeLine(digester.Hash(), k, i.index[k])
		}
		i.digests[a] = digester.Digest()
	}

	return i.digests[a]
}

// Verify returns true if the index matches the provided digest.
func (i *Digester) Verify(d digest.Digest) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	verifier := d.Verifier()
	keys := i.sortedKeys()
	for _, k := range keys {
		_, _ = writeLine(verifier, k, i.index[k])
	}
	return verifier.Verified()
}

// sortedKeys returns a slice of the keys in the index, sorted alphabetically.
func (i *Digester) sortedKeys() []string {
	keys := make([]string, 0, len(i.index))
	for k := range i.index {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// reset clears the digests cache.
func (i *Digester) reset() {
	i.digests = make(map[digest.Algorithm]digest.Digest, 0)
}

// writeLine writes the key and digest to the writer, separated by a space and
// terminating with a newline.
func writeLine(w io.Writer, key, value string) (int, error) {
	return fmt.Fprintf(w, "%s %s\n", key, value)
}
