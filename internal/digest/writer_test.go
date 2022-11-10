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
	"crypto/rand"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
)

func TestNewMultiDigester(t *testing.T) {
	t.Run("constructs a MultiDigester", func(t *testing.T) {
		g := NewWithT(t)

		d, err := NewMultiDigester(Canonical, digest.SHA512)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(d.d).To(HaveLen(2))
	})

	t.Run("returns an error if an algorithm is not available", func(t *testing.T) {
		g := NewWithT(t)

		_, err := NewMultiDigester(digest.Algorithm("not-available"))
		g.Expect(err).To(HaveOccurred())
	})
}

func TestMultiDigester_Write(t *testing.T) {
	t.Run("writes to all digesters", func(t *testing.T) {
		g := NewWithT(t)

		d, err := NewMultiDigester(Canonical, digest.SHA512)
		g.Expect(err).ToNot(HaveOccurred())

		n, err := d.Write([]byte("hello"))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(n).To(Equal(5))

		n, err = d.Write([]byte(" world"))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(n).To(Equal(6))

		g.Expect(d.Digest(Canonical)).To(BeEquivalentTo("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"))
		g.Expect(d.Digest(digest.SHA512)).To(BeEquivalentTo("sha512:309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"))
	})
}

func TestMultiDigester_Digest(t *testing.T) {
	t.Run("returns the digest for the given algorithm", func(t *testing.T) {
		g := NewWithT(t)

		d, err := NewMultiDigester(Canonical, digest.SHA512)
		g.Expect(err).ToNot(HaveOccurred())

		g.Expect(d.Digest(Canonical)).To(BeEquivalentTo("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
		g.Expect(d.Digest(digest.SHA512)).To(BeEquivalentTo("sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))
	})

	t.Run("returns an empty digest if the algorithm is not supported", func(t *testing.T) {
		g := NewWithT(t)

		d, err := NewMultiDigester(Canonical, digest.SHA512)
		g.Expect(err).ToNot(HaveOccurred())

		g.Expect(d.Digest(digest.Algorithm("not-available"))).To(BeEmpty())
	})
}

func benchmarkMultiDigesterWrite(b *testing.B, algos []digest.Algorithm, pSize int64) {
	md, err := NewMultiDigester(algos...)
	if err != nil {
		b.Fatal(err)
	}

	p := make([]byte, pSize)
	if _, err = rand.Read(p); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md.Write(p)
	}
}

func BenchmarkMultiDigester_Write(b *testing.B) {
	const pSize = 1024 * 2

	b.Run("sha1", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{SHA1}, pSize)
	})

	b.Run("sha256", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{digest.SHA256}, pSize)
	})

	b.Run("blake3", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{digest.BLAKE3}, pSize)
	})

	b.Run("sha256+sha384", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{digest.SHA256, digest.SHA384}, pSize)
	})

	b.Run("sha256+sha512", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{digest.SHA256, digest.SHA512}, pSize)
	})

	b.Run("sha256+blake3", func(b *testing.B) {
		benchmarkMultiDigesterWrite(b, []digest.Algorithm{digest.SHA256, digest.BLAKE3}, pSize)
	})
}
