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
	"bytes"
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
)

func TestWithIndex(t *testing.T) {
	t.Run("sets the index", func(t *testing.T) {
		g := NewWithT(t)

		i := map[string]string{"foo": "bar"}
		d := &Digester{}
		WithIndex(i)(d)

		g.Expect(d.index).To(Equal(i))
	})

	t.Run("resets the digests", func(t *testing.T) {
		g := NewWithT(t)

		i := map[string]string{"foo": "bar"}
		d := &Digester{
			digests: map[digest.Algorithm]digest.Digest{
				digest.SHA256: "sha256:foo",
			},
		}
		WithIndex(i)(d)

		g.Expect(d.digests).To(BeEmpty())
	})

	t.Run("handles nil index", func(t *testing.T) {
		g := NewWithT(t)
		d := &Digester{}
		WithIndex(nil)(d)
		g.Expect(d.index).To(BeNil())
	})
}

func TestNewDigester(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester()

		g.Expect(d).ToNot(BeNil())
		g.Expect(d.index).ToNot(BeNil())
		g.Expect(d.digests).ToNot(BeNil())
	})

	t.Run("with index", func(t *testing.T) {
		g := NewWithT(t)

		i := map[string]string{"foo": "bar"}
		d := NewDigester(WithIndex(i))

		g.Expect(d).ToNot(BeNil())
		g.Expect(d.index).To(Equal(i))
		g.Expect(d.digests).ToNot(BeNil())
	})
}

func TestDigester_Add(t *testing.T) {
	t.Run("adds", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester()
		d.Add("foo", "bar")

		g.Expect(d.index).To(HaveKeyWithValue("foo", "bar"))
	})

	t.Run("overwrites", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester()
		d.Add("foo", "bar")
		d.Add("foo", "baz")

		g.Expect(d.index).To(HaveKeyWithValue("foo", "baz"))
	})

	t.Run("resets digests", func(t *testing.T) {
		g := NewWithT(t)

		d := &Digester{
			index: map[string]string{},
			digests: map[digest.Algorithm]digest.Digest{
				digest.SHA256: "sha256:foo",
			},
		}
		d.Add("foo", "bar")

		g.Expect(d.digests).To(BeEmpty())
	})

	t.Run("adds empty key and value", func(t *testing.T) {
		g := NewWithT(t)
		d := NewDigester()
		d.Add("", "")
		g.Expect(d.index).To(HaveKeyWithValue("", ""))
	})
}

func TestDigester_Delete(t *testing.T) {
	t.Run("deletes", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester()
		d.Add("foo", "bar")
		d.Delete("foo")

		g.Expect(d.index).ToNot(HaveKey("foo"))
	})

	t.Run("resets digests", func(t *testing.T) {
		g := NewWithT(t)

		d := &Digester{
			index: map[string]string{
				"foo": "bar",
			},
			digests: map[digest.Algorithm]digest.Digest{
				digest.SHA256: "sha256:foo",
			},
		}

		d.Delete("nop")
		g.Expect(d.digests).To(HaveLen(1))

		d.Delete("foo")
		g.Expect(d.digests).To(BeEmpty())
	})

	t.Run("deletes non-existent key without error", func(t *testing.T) {
		g := NewWithT(t)
		d := NewDigester()
		d.Delete("non-existent")
		g.Expect(d.index).To(BeEmpty())
		g.Expect(d.digests).To(BeEmpty())
	})
}

func TestDigester_Get(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester()
	d.Add("foo", "bar")

	g.Expect(d.Get("foo")).To(Equal("bar"))
	g.Expect(d.Get("bar")).To(BeEmpty())
}

func TestDigester_Has(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester()
	d.Add("foo", "bar")

	g.Expect(d.Has("foo")).To(BeTrue())
	g.Expect(d.Has("bar")).To(BeFalse())
}

func TestDigester_Index(t *testing.T) {
	t.Run("returns a copy of the index", func(t *testing.T) {
		g := NewWithT(t)

		i := map[string]string{
			"foo": "bar",
			"bar": "baz",
		}
		d := NewDigester(WithIndex(i))

		iCopy := d.Index()
		g.Expect(iCopy).To(Equal(i))
		g.Expect(iCopy).ToNot(BeIdenticalTo(i))
	})

	t.Run("returns an empty copy for an empty index", func(t *testing.T) {
		g := NewWithT(t)
		d := NewDigester()
		emptyIndex := d.Index()
		g.Expect(emptyIndex).To(BeEmpty())
	})
}

func TestDigester_Len(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester(WithIndex(map[string]string{
		"foo": "bar",
		"bar": "baz",
	}))

	g.Expect(d.Len()).To(Equal(2))

	g.Expect(NewDigester().Len()).To(Equal(0))
}

func TestDigester_String(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester(WithIndex(map[string]string{
		"foo": "bar",
		"bar": "baz",
	}))

	g.Expect(d.String()).To(Equal(`bar baz
foo bar
`))

	g.Expect(NewDigester().String()).To(Equal(""))
}

func TestDigester_WriteTo(t *testing.T) {
	t.Run("writes", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester(WithIndex(map[string]string{
			"foo": "bar",
			"bar": "baz",
		}))
		expect := `bar baz
foo bar
`

		var buf bytes.Buffer
		n, err := d.WriteTo(&buf)

		g.Expect(n).To(Equal(int64(len(expect))))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(buf.String()).To(Equal(expect))
	})

	t.Run("errors", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester(WithIndex(map[string]string{
			"foo": "bar",
			"bar": "baz",
		}))

		w := &fakeWriter{
			err:     errors.New("write error"),
			written: 5,
		}
		n, err := d.WriteTo(w)

		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, w.err)).To(BeTrue())
		g.Expect(n).To(Equal(int64(w.written)))
	})
}

func TestDigester_Digest(t *testing.T) {
	t.Run("returns digest", func(t *testing.T) {
		g := NewWithT(t)

		d := NewDigester(WithIndex(map[string]string{
			"foo": "bar",
			"bar": "baz",
		}))
		expect := digest.SHA256.FromString(d.String())

		g.Expect(d.Digest(digest.SHA256)).To(Equal(expect))
		g.Expect(d.digests).To(HaveKeyWithValue(digest.SHA256, expect))
	})

	t.Run("returns cached digest", func(t *testing.T) {
		g := NewWithT(t)

		d := &Digester{
			index: map[string]string{
				"foo": "bar",
				"bar": "baz",
			},
			digests: map[digest.Algorithm]digest.Digest{
				digest.SHA256: "sha256:foo",
			},
		}

		g.Expect(d.Digest(digest.SHA256)).To(Equal(d.digests[digest.SHA256]))
	})
}

func TestDigester_Verify(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester(WithIndex(map[string]string{
		"foo": "bar",
	}))

	g.Expect(d.Verify(d.Digest(digest.SHA256))).To(BeTrue())
	g.Expect(d.Verify(digest.SHA256.FromString("different"))).To(BeFalse())
}

func TestDigester_sortedKeys(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester(WithIndex(map[string]string{
		"c/d/e": "bar",
		"a/b/c": "baz",
		"f/g/h": "foo",
	}))

	g.Expect(d.sortedKeys()).To(Equal([]string{
		"a/b/c",
		"c/d/e",
		"f/g/h",
	}))
}

func TestDigester_reset(t *testing.T) {
	g := NewWithT(t)

	d := NewDigester()
	d.digests = map[digest.Algorithm]digest.Digest{
		digest.SHA256: "sha256:foo",
	}

	d.reset()
	g.Expect(d.digests).To(BeEmpty())
}

func Test_writeLine(t *testing.T) {
	t.Run("writes", func(t *testing.T) {
		g := NewWithT(t)

		var buf bytes.Buffer
		n, err := writeLine(&buf, "foo", "bar")

		g.Expect(n).To(Equal(8))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(buf.String()).To(Equal(`foo bar
`))
	})

	t.Run("errors", func(t *testing.T) {
		g := NewWithT(t)

		w := &fakeWriter{
			err:     errors.New("write error"),
			written: 5,
		}
		n, err := writeLine(w, "foo", "bar")

		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, w.err)).To(BeTrue())
		g.Expect(n).To(Equal(w.written))
	})
}

type fakeWriter struct {
	written int
	err     error
}

func (f *fakeWriter) Write(p []byte) (n int, err error) {
	return f.written, f.err
}
