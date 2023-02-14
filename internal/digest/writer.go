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

package digest

import (
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
)

// MultiDigester is a digester that writes to multiple digesters to calculate
// the checksum of different algorithms.
type MultiDigester struct {
	d map[digest.Algorithm]digest.Digester
}

// NewMultiDigester returns a new MultiDigester that writes to newly
// initialized digesters for the given algorithms. If a provided algorithm is
// not available, it returns a digest.ErrDigestUnsupported error.
func NewMultiDigester(algos ...digest.Algorithm) (*MultiDigester, error) {
	d := make(map[digest.Algorithm]digest.Digester, len(algos))
	for _, a := range algos {
		if _, ok := d[a]; ok {
			continue
		}
		if !a.Available() {
			return nil, fmt.Errorf("%w: %s", digest.ErrDigestUnsupported, a)
		}
		d[a] = a.Digester()
	}
	return &MultiDigester{d: d}, nil
}

// Write writes p to all underlying digesters.
func (w *MultiDigester) Write(p []byte) (n int, err error) {
	for _, d := range w.d {
		n, err = d.Hash().Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

// Digest returns the digest of the data written to the digester of the given
// algorithm, or an empty digest if the algorithm is not available.
func (w *MultiDigester) Digest(algo digest.Algorithm) digest.Digest {
	if d, ok := w.d[algo]; ok {
		return d.Digest()
	}
	return ""
}
