/*
Copyright 2020, 2021 The Flux authors

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

package controllers

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

func createStoragePath() (string, error) {
	return ioutil.TempDir("", "")
}

func cleanupStoragePath(dir string) func() {
	return func() { os.RemoveAll(dir) }
}

func TestStorageConstructor(t *testing.T) {
	dir, err := createStoragePath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanupStoragePath(dir))

	if _, err := NewStorage("/nonexistent", "hostname", time.Minute); err == nil {
		t.Fatal("nonexistent path was allowable in storage constructor")
	}

	f, err := ioutil.TempFile(dir, "")
	if err != nil {
		t.Fatalf("while creating temporary file: %v", err)
	}
	f.Close()

	if _, err := NewStorage(f.Name(), "hostname", time.Minute); err == nil {
		os.Remove(f.Name())
		t.Fatal("file path was accepted as basedir")
	}
	os.Remove(f.Name())

	if _, err := NewStorage(dir, "hostname", time.Minute); err != nil {
		t.Fatalf("Valid path did not successfully return: %v", err)
	}
}

// walks a tar.gz and looks for paths with the basename. It does not match
// symlinks properly at this time because that's painful.
func walkTar(tarFile string, match string) (int64, bool, error) {
	f, err := os.Open(tarFile)
	if err != nil {
		return 0, false, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, false, fmt.Errorf("could not unzip file: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return 0, false, fmt.Errorf("corrupt tarball reading header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			if header.Name == match {
				return header.Size, true, nil
			}
		default:
			// skip
		}
	}

	return 0, false, nil
}

func TestStorage_Archive(t *testing.T) {
	dir, err := createStoragePath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanupStoragePath(dir))

	storage, err := NewStorage(dir, "hostname", time.Minute)
	if err != nil {
		t.Fatalf("error while bootstrapping storage: %v", err)
	}

	createFiles := func(files map[string][]byte) (dir string, err error) {
		defer func() {
			if err != nil && dir != "" {
				os.RemoveAll(dir)
			}
		}()
		dir, err = ioutil.TempDir("", "archive-test-files-")
		if err != nil {
			return
		}
		for name, b := range files {
			absPath := filepath.Join(dir, name)
			if err = os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
				return
			}
			f, err := os.Create(absPath)
			if err != nil {
				return "", fmt.Errorf("could not create file %q: %w", absPath, err)
			}
			if n, err := f.Write(b); err != nil {
				f.Close()
				return "", fmt.Errorf("could not write %d bytes to file %q: %w", n, f.Name(), err)
			}
			f.Close()
		}
		return
	}

	matchFiles := func(t *testing.T, storage *Storage, artifact sourcev1.Artifact, files map[string][]byte) {
		for name, b := range files {
			mustExist := !(name[0:1] == "!")
			if !mustExist {
				name = name[1:]
			}
			s, exist, err := walkTar(storage.LocalPath(artifact), name)
			if err != nil {
				t.Fatalf("failed reading tarball: %v", err)
			}
			if bs := int64(len(b)); s != bs {
				t.Fatalf("%q size %v != %v", name, s, bs)
			}
			if exist != mustExist {
				if mustExist {
					t.Errorf("could not find file %q in tarball", name)
				} else {
					t.Errorf("tarball contained excluded file %q", name)
				}
			}
		}
	}

	tests := []struct {
		name    string
		files   map[string][]byte
		filter  ArchiveFileFilter
		want    map[string][]byte
		wantErr bool
	}{
		{
			name: "no filter",
			files: map[string][]byte{
				".git/config":   nil,
				"file.jpg":      []byte(`contents`),
				"manifest.yaml": nil,
			},
			filter: nil,
			want: map[string][]byte{
				".git/config":   nil,
				"file.jpg":      []byte(`contents`),
				"manifest.yaml": nil,
			},
		},
		{
			name: "exclude VCS",
			files: map[string][]byte{
				".git/config":   nil,
				"manifest.yaml": nil,
			},
			filter: SourceIgnoreFilter(nil, nil),
			want: map[string][]byte{
				"!.git/config":  nil,
				"manifest.yaml": nil,
			},
		},
		{
			name: "custom",
			files: map[string][]byte{
				".git/config": nil,
				"custom":      nil,
				"horse.jpg":   nil,
			},
			filter: SourceIgnoreFilter([]gitignore.Pattern{
				gitignore.ParsePattern("custom", nil),
			}, nil),
			want: map[string][]byte{
				"!git/config": nil,
				"!custom":     nil,
				"horse.jpg":   nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := createFiles(tt.files)
			if err != nil {
				t.Error(err)
				return
			}
			defer os.RemoveAll(dir)
			artifact := sourcev1.Artifact{
				Path: filepath.Join(randStringRunes(10), randStringRunes(10), randStringRunes(10)+".tar.gz"),
			}
			if err := storage.MkdirAll(artifact); err != nil {
				t.Fatalf("artifact directory creation failed: %v", err)
			}
			if err := storage.Archive(&artifact, dir, tt.filter); (err != nil) != tt.wantErr {
				t.Errorf("Archive() error = %v, wantErr %v", err, tt.wantErr)
			}
			matchFiles(t, storage, artifact, tt.want)
		})
	}
}

func TestStorageRemoveAllButCurrent(t *testing.T) {
	t.Run("bad directory in archive", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })

		s, err := NewStorage(dir, "hostname", time.Minute)
		if err != nil {
			t.Fatalf("Valid path did not successfully return: %v", err)
		}

		if err := s.RemoveAllButCurrent(sourcev1.Artifact{Path: path.Join(dir, "really", "nonexistent")}); err == nil {
			t.Fatal("Did not error while pruning non-existent path")
		}
	})
}
