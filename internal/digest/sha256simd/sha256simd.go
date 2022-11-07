package sha256simd

import (
	"github.com/minio/sha256-simd"
	"github.com/opencontainers/go-digest"
	"hash"
)

const SHA256SIMD = digest.Algorithm("sha256simd")

func init() {
	digest.RegisterAlgorithm(SHA256SIMD, &sha256simdhash{})
}

type sha256simdhash struct{}

func (sha256simdhash) Available() bool {
	return true
}

func (sha256simdhash) Size() int {
	return sha256.Size
}

func (sha256simdhash) New() hash.Hash {
	return sha256.New()
}
