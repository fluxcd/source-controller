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

package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/go-git/v5/plumbing/format/gitignore"
	. "github.com/onsi/gomega"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

func TestStorageConstructor(t *testing.T) {
	dir := t.TempDir()

	if _, err := NewStorage("/nonexistent", "hostname", time.Minute, 2); err == nil {
		t.Fatal("nonexistent path was allowable in storage constructor")
	}

	f, err := os.CreateTemp(dir, "")
	if err != nil {
		t.Fatalf("while creating temporary file: %v", err)
	}
	f.Close()

	if _, err := NewStorage(f.Name(), "hostname", time.Minute, 2); err == nil {
		os.Remove(f.Name())
		t.Fatal("file path was accepted as basedir")
	}
	os.Remove(f.Name())

	if _, err := NewStorage(dir, "hostname", time.Minute, 2); err != nil {
		t.Fatalf("Valid path did not successfully return: %v", err)
	}
}

// walks a tar.gz and looks for paths with the basename. It does not match
// symlinks properly at this time because that's painful.
func walkTar(tarFile string, match string, dir bool) (int64, int64, bool, error) {
	f, err := os.Open(tarFile)
	if err != nil {
		return 0, 0, false, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, false, fmt.Errorf("could not unzip file: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return 0, 0, false, fmt.Errorf("corrupt tarball reading header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if header.Name == match && dir {
				return 0, header.Mode, true, nil
			}
		case tar.TypeReg:
			if header.Name == match {
				return header.Size, header.Mode, true, nil
			}
		default:
			// skip
		}
	}

	return 0, 0, false, nil
}

func TestStorage_Archive(t *testing.T) {
	dir := t.TempDir()

	storage, err := NewStorage(dir, "hostname", time.Minute, 2)
	if err != nil {
		t.Fatalf("error while bootstrapping storage: %v", err)
	}

	createFiles := func(files map[string][]byte) (dir string, err error) {
		dir = t.TempDir()
		for name, b := range files {
			absPath := filepath.Join(dir, name)
			if err = os.MkdirAll(filepath.Dir(absPath), 0o750); err != nil {
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

	matchFiles := func(t *testing.T, storage *Storage, artifact sourcev1.Artifact, files map[string][]byte, dirs []string) {
		t.Helper()
		for name, b := range files {
			mustExist := !(name[0:1] == "!")
			if !mustExist {
				name = name[1:]
			}
			s, m, exist, err := walkTar(storage.LocalPath(artifact), name, false)
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
			if exist && m != defaultFileMode {
				t.Fatalf("%q mode %v != %v", name, m, defaultFileMode)
			}
		}
		for _, name := range dirs {
			mustExist := !(name[0:1] == "!")
			if !mustExist {
				name = name[1:]
			}
			_, m, exist, err := walkTar(storage.LocalPath(artifact), name, true)
			if err != nil {
				t.Fatalf("failed reading tarball: %v", err)
			}
			if exist != mustExist {
				if mustExist {
					t.Errorf("could not find dir %q in tarball", name)
				} else {
					t.Errorf("tarball contained excluded file %q", name)
				}
			}
			if exist && m != defaultDirMode {
				t.Fatalf("%q mode %v != %v", name, m, defaultDirMode)
			}

		}
	}

	tests := []struct {
		name     string
		files    map[string][]byte
		filter   ArchiveFileFilter
		want     map[string][]byte
		wantDirs []string
		wantErr  bool
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
			wantDirs: []string{
				"!.git",
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
		{
			name: "including directories",
			files: map[string][]byte{
				"test/.gitkeep": nil,
			},
			filter: SourceIgnoreFilter([]gitignore.Pattern{
				gitignore.ParsePattern("custom", nil),
			}, nil),
			wantDirs: []string{
				"test",
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
			matchFiles(t, storage, artifact, tt.want, tt.wantDirs)
		})
	}
}

func TestStorage_Remove(t *testing.T) {
	t.Run("removes file", func(t *testing.T) {
		g := NewWithT(t)

		dir := t.TempDir()

		s, err := NewStorage(dir, "", 0, 0)
		g.Expect(err).ToNot(HaveOccurred())

		artifact := sourcev1.Artifact{
			Path: filepath.Join(dir, "test.txt"),
		}
		g.Expect(s.MkdirAll(artifact)).To(Succeed())
		g.Expect(s.AtomicWriteFile(&artifact, bytes.NewReader([]byte("test")), 0o600)).To(Succeed())
		g.Expect(s.ArtifactExist(artifact)).To(BeTrue())

		g.Expect(s.Remove(artifact)).To(Succeed())
		g.Expect(s.ArtifactExist(artifact)).To(BeFalse())
	})

	t.Run("error if file does not exist", func(t *testing.T) {
		g := NewWithT(t)

		dir := t.TempDir()

		s, err := NewStorage(dir, "", 0, 0)
		g.Expect(err).ToNot(HaveOccurred())

		artifact := sourcev1.Artifact{
			Path: filepath.Join(dir, "test.txt"),
		}

		err = s.Remove(artifact)
		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue())
	})
}

func TestStorageRemoveAllButCurrent(t *testing.T) {
	t.Run("bad directory in archive", func(t *testing.T) {
		dir := t.TempDir()

		s, err := NewStorage(dir, "hostname", time.Minute, 2)
		if err != nil {
			t.Fatalf("Valid path did not successfully return: %v", err)
		}

		if _, err := s.RemoveAllButCurrent(sourcev1.Artifact{Path: filepath.Join(dir, "really", "nonexistent")}); err == nil {
			t.Fatal("Did not error while pruning non-existent path")
		}
	})

	t.Run("collect names of deleted items", func(t *testing.T) {
		g := NewWithT(t)
		dir := t.TempDir()

		s, err := NewStorage(dir, "hostname", time.Minute, 2)
		g.Expect(err).ToNot(HaveOccurred(), "failed to create new storage")

		artifact := sourcev1.Artifact{
			Path: filepath.Join("foo", "bar", "artifact1.tar.gz"),
		}

		// Create artifact dir and artifacts.
		artifactDir := filepath.Join(dir, "foo", "bar")
		g.Expect(os.MkdirAll(artifactDir, 0o750)).NotTo(HaveOccurred())
		current := []string{
			filepath.Join(artifactDir, "artifact1.tar.gz"),
		}
		wantDeleted := []string{
			filepath.Join(artifactDir, "file1.txt"),
			filepath.Join(artifactDir, "file2.txt"),
		}
		createFile := func(files []string) {
			for _, c := range files {
				f, err := os.Create(c)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(f.Close()).ToNot(HaveOccurred())
			}
		}
		createFile(current)
		createFile(wantDeleted)
		_, err = s.Symlink(artifact, "latest.tar.gz")
		g.Expect(err).ToNot(HaveOccurred(), "failed to create symlink")

		deleted, err := s.RemoveAllButCurrent(artifact)
		g.Expect(err).ToNot(HaveOccurred(), "failed to remove all but current")
		g.Expect(deleted).To(Equal(wantDeleted))
	})
}

func TestStorageRemoveAll(t *testing.T) {
	tests := []struct {
		name               string
		artifactPath       string
		createArtifactPath bool
		wantDeleted        string
	}{
		{
			name:               "delete non-existent path",
			artifactPath:       filepath.Join("foo", "bar", "artifact1.tar.gz"),
			createArtifactPath: false,
			wantDeleted:        "",
		},
		{
			name:               "delete existing path",
			artifactPath:       filepath.Join("foo", "bar", "artifact1.tar.gz"),
			createArtifactPath: true,
			wantDeleted:        filepath.Join("foo", "bar"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			dir := t.TempDir()

			s, err := NewStorage(dir, "hostname", time.Minute, 2)
			g.Expect(err).ToNot(HaveOccurred(), "failed to create new storage")

			artifact := sourcev1.Artifact{
				Path: tt.artifactPath,
			}

			if tt.createArtifactPath {
				g.Expect(os.MkdirAll(filepath.Join(dir, tt.artifactPath), 0o750)).ToNot(HaveOccurred())
			}

			deleted, err := s.RemoveAll(artifact)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(deleted).To(ContainSubstring(tt.wantDeleted), "unexpected deleted path")
		})
	}
}

func TestStorageCopyFromPath(t *testing.T) {
	type File struct {
		Name    string
		Content []byte
	}

	dir := t.TempDir()

	storage, err := NewStorage(dir, "hostname", time.Minute, 2)
	if err != nil {
		t.Fatalf("error while bootstrapping storage: %v", err)
	}

	createFile := func(file *File) (absPath string, err error) {
		dir = t.TempDir()
		absPath = filepath.Join(dir, file.Name)
		if err = os.MkdirAll(filepath.Dir(absPath), 0o750); err != nil {
			return
		}
		f, err := os.Create(absPath)
		if err != nil {
			return "", fmt.Errorf("could not create file %q: %w", absPath, err)
		}
		if n, err := f.Write(file.Content); err != nil {
			f.Close()
			return "", fmt.Errorf("could not write %d bytes to file %q: %w", n, f.Name(), err)
		}
		f.Close()
		return
	}

	matchFile := func(t *testing.T, storage *Storage, artifact sourcev1.Artifact, file *File, expectMismatch bool) {
		c, err := os.ReadFile(storage.LocalPath(artifact))
		if err != nil {
			t.Fatalf("failed reading file: %v", err)
		}
		if (string(c) != string(file.Content)) != expectMismatch {
			t.Errorf("artifact content does not match and not expecting mismatch, got: %q, want: %q", string(c), string(file.Content))
		}
	}

	tests := []struct {
		name           string
		file           *File
		want           *File
		expectMismatch bool
	}{
		{
			name: "content match",
			file: &File{
				Name:    "manifest.yaml",
				Content: []byte(`contents`),
			},
			want: &File{
				Name:    "manifest.yaml",
				Content: []byte(`contents`),
			},
		},
		{
			name: "content not match",
			file: &File{
				Name:    "manifest.yaml",
				Content: []byte(`contents`),
			},
			want: &File{
				Name:    "manifest.yaml",
				Content: []byte(`mismatch contents`),
			},
			expectMismatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absPath, err := createFile(tt.file)
			if err != nil {
				t.Error(err)
				return
			}
			artifact := sourcev1.Artifact{
				Path: filepath.Join(randStringRunes(10), randStringRunes(10), randStringRunes(10)),
			}
			if err := storage.MkdirAll(artifact); err != nil {
				t.Fatalf("artifact directory creation failed: %v", err)
			}
			if err := storage.CopyFromPath(&artifact, absPath); err != nil {
				t.Errorf("CopyFromPath() error = %v", err)
			}
			matchFile(t, storage, artifact, tt.want, tt.expectMismatch)
		})
	}
}

func TestStorage_getGarbageFiles(t *testing.T) {
	artifactFolder := filepath.Join("foo", "bar")
	tests := []struct {
		name                 string
		artifactPaths        []string
		createPause          time.Duration
		ttl                  time.Duration
		maxItemsToBeRetained int
		totalCountLimit      int
		wantDeleted          []string
	}{
		{
			name: "delete files based on maxItemsToBeRetained",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
			},
			createPause:          time.Millisecond * 10,
			ttl:                  time.Minute * 2,
			totalCountLimit:      10,
			maxItemsToBeRetained: 2,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
			},
		},
		{
			name: "delete files based on maxItemsToBeRetained, ignore lock files",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact1.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
			},
			createPause:          time.Millisecond * 10,
			ttl:                  time.Minute * 2,
			totalCountLimit:      10,
			maxItemsToBeRetained: 2,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
			},
		},
		{
			name: "delete files based on ttl",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
			},
			createPause:          time.Second * 1,
			ttl:                  time.Second*3 + time.Millisecond*500,
			totalCountLimit:      10,
			maxItemsToBeRetained: 4,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
			},
		},
		{
			name: "delete files based on ttl, ignore lock files",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact1.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
			},
			createPause:          time.Second * 1,
			ttl:                  time.Second*3 + time.Millisecond*500,
			totalCountLimit:      10,
			maxItemsToBeRetained: 4,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
			},
		},
		{
			name: "delete files based on ttl and maxItemsToBeRetained",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
				filepath.Join(artifactFolder, "artifact6.tar.gz"),
			},
			createPause:          time.Second * 1,
			ttl:                  time.Second*5 + time.Millisecond*500,
			totalCountLimit:      10,
			maxItemsToBeRetained: 4,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
			},
		},
		{
			name: "delete files based on ttl and maxItemsToBeRetained and totalCountLimit",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
				filepath.Join(artifactFolder, "artifact5.tar.gz"),
				filepath.Join(artifactFolder, "artifact6.tar.gz"),
			},
			createPause:          time.Millisecond * 500,
			ttl:                  time.Millisecond * 500,
			totalCountLimit:      3,
			maxItemsToBeRetained: 2,
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			dir := t.TempDir()

			s, err := NewStorage(dir, "hostname", tt.ttl, tt.maxItemsToBeRetained)
			g.Expect(err).ToNot(HaveOccurred(), "failed to create new storage")

			artifact := sourcev1.Artifact{
				Path: tt.artifactPaths[len(tt.artifactPaths)-1],
			}
			g.Expect(os.MkdirAll(filepath.Join(dir, artifactFolder), 0o750)).ToNot(HaveOccurred())
			for _, artifactPath := range tt.artifactPaths {
				f, err := os.Create(filepath.Join(dir, artifactPath))
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(f.Close()).ToNot(HaveOccurred())
				time.Sleep(tt.createPause)
			}

			deletedPaths, err := s.getGarbageFiles(artifact, tt.totalCountLimit, tt.maxItemsToBeRetained, tt.ttl)
			g.Expect(err).ToNot(HaveOccurred(), "failed to collect garbage files")
			g.Expect(len(tt.wantDeleted)).To(Equal(len(deletedPaths)))
			for _, wantDeletedPath := range tt.wantDeleted {
				present := false
				for _, deletedPath := range deletedPaths {
					if strings.Contains(deletedPath, wantDeletedPath) {
						present = true
						break
					}
				}
				if !present {
					g.Fail(fmt.Sprintf("expected file to be deleted, still exists: %s", wantDeletedPath))
				}
			}
		})
	}
}

func TestStorage_GarbageCollect(t *testing.T) {
	artifactFolder := filepath.Join("foo", "bar")
	tests := []struct {
		name          string
		artifactPaths []string
		wantCollected []string
		wantDeleted   []string
		wantErr       string
		ctxTimeout    time.Duration
	}{
		{
			name: "garbage collects",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact1.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
			},
			wantCollected: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
			},
			wantDeleted: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact1.tar.gz.lock"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz.lock"),
			},
			ctxTimeout: time.Second * 1,
		},
		{
			name: "garbage collection fails with context timeout",
			artifactPaths: []string{
				filepath.Join(artifactFolder, "artifact1.tar.gz"),
				filepath.Join(artifactFolder, "artifact2.tar.gz"),
				filepath.Join(artifactFolder, "artifact3.tar.gz"),
				filepath.Join(artifactFolder, "artifact4.tar.gz"),
			},
			wantErr:    "context deadline exceeded",
			ctxTimeout: time.Nanosecond * 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			dir := t.TempDir()

			s, err := NewStorage(dir, "hostname", time.Second*2, 2)
			g.Expect(err).ToNot(HaveOccurred(), "failed to create new storage")

			artifact := sourcev1.Artifact{
				Path: tt.artifactPaths[len(tt.artifactPaths)-1],
			}
			g.Expect(os.MkdirAll(filepath.Join(dir, artifactFolder), 0o750)).ToNot(HaveOccurred())
			for i, artifactPath := range tt.artifactPaths {
				f, err := os.Create(filepath.Join(dir, artifactPath))
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(f.Close()).ToNot(HaveOccurred())
				if i != len(tt.artifactPaths)-1 {
					time.Sleep(time.Second * 1)
				}
			}

			collectedPaths, err := s.GarbageCollect(context.TODO(), artifact, tt.ctxTimeout)
			if tt.wantErr == "" {
				g.Expect(err).ToNot(HaveOccurred(), "failed to collect garbage files")
			} else {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
			}
			if len(tt.wantCollected) > 0 {
				g.Expect(len(tt.wantCollected)).To(Equal(len(collectedPaths)))
				for _, wantCollectedPath := range tt.wantCollected {
					present := false
					for _, collectedPath := range collectedPaths {
						if strings.Contains(collectedPath, wantCollectedPath) {
							g.Expect(collectedPath).ToNot(BeAnExistingFile())
							present = true
							break
						}
					}
					if present == false {
						g.Fail(fmt.Sprintf("expected file to be garbage collected, still exists: %s", wantCollectedPath))
					}
				}
			}
			for _, delFile := range tt.wantDeleted {
				g.Expect(filepath.Join(dir, delFile)).ToNot(BeAnExistingFile())
			}
		})
	}
}

func TestStorage_VerifyArtifact(t *testing.T) {
	g := NewWithT(t)

	dir := t.TempDir()
	s, err := NewStorage(dir, "", 0, 0)
	g.Expect(err).ToNot(HaveOccurred(), "failed to create new storage")

	g.Expect(os.WriteFile(filepath.Join(dir, "artifact"), []byte("test"), 0o600)).To(Succeed())

	t.Run("artifact without digest", func(t *testing.T) {
		g := NewWithT(t)

		err := s.VerifyArtifact(sourcev1.Artifact{})
		g.Expect(err).To(HaveOccurred())
		g.Expect(err).To(MatchError("artifact has no digest"))
	})

	t.Run("artifact with invalid digest", func(t *testing.T) {
		g := NewWithT(t)

		err := s.VerifyArtifact(sourcev1.Artifact{Digest: "invalid"})
		g.Expect(err).To(HaveOccurred())
		g.Expect(err).To(MatchError("failed to parse artifact digest 'invalid': invalid checksum digest format"))
	})

	t.Run("artifact with invalid path", func(t *testing.T) {
		g := NewWithT(t)

		err := s.VerifyArtifact(sourcev1.Artifact{
			Digest: "sha256:9ba7a35ce8acd3557fe30680ef193ca7a36bb5dc62788f30de7122a0a5beab69",
			Path:   "invalid",
		})
		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue())
	})

	t.Run("artifact with digest mismatch", func(t *testing.T) {
		g := NewWithT(t)

		err := s.VerifyArtifact(sourcev1.Artifact{
			Digest: "sha256:9ba7a35ce8acd3557fe30680ef193ca7a36bb5dc62788f30de7122a0a5beab69",
			Path:   "artifact",
		})
		g.Expect(err).To(HaveOccurred())
		g.Expect(err).To(MatchError("computed digest doesn't match 'sha256:9ba7a35ce8acd3557fe30680ef193ca7a36bb5dc62788f30de7122a0a5beab69'"))
	})

	t.Run("artifact with digest match", func(t *testing.T) {
		g := NewWithT(t)

		err := s.VerifyArtifact(sourcev1.Artifact{
			Digest: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			Path:   "artifact",
		})
		g.Expect(err).ToNot(HaveOccurred())
	})
}
