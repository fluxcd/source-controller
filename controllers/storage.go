/*
Copyright 2020 The Flux authors

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
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fluxcd/pkg/lockedfile"

	"github.com/fluxcd/pkg/untar"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/fs"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// Storage manages artifacts
type Storage struct {
	// BasePath is the local directory path where the source artifacts are stored.
	BasePath string `json:"basePath"`

	// Hostname is the file server host name used to compose the artifacts URIs.
	Hostname string `json:"hostname"`

	// Timeout for artifacts operations
	Timeout time.Duration `json:"timeout"`
}

// NewStorage creates the storage helper for a given path and hostname.
func NewStorage(basePath string, hostname string, timeout time.Duration) (*Storage, error) {
	if f, err := os.Stat(basePath); os.IsNotExist(err) || !f.IsDir() {
		return nil, fmt.Errorf("invalid dir path: %s", basePath)
	}
	return &Storage{
		BasePath: basePath,
		Hostname: hostname,
		Timeout:  timeout,
	}, nil
}

// NewArtifactFor returns a new v1beta1.Artifact.
func (s *Storage) NewArtifactFor(kind string, metadata metav1.Object, revision, fileName string) sourcev1.Artifact {
	path := sourcev1.ArtifactPath(kind, metadata.GetNamespace(), metadata.GetName(), fileName)
	artifact := sourcev1.Artifact{
		Path:     path,
		Revision: revision,
	}
	s.SetArtifactURL(&artifact)
	return artifact
}

// SetArtifactURL sets the URL on the given v1beta1.Artifact.
func (s Storage) SetArtifactURL(artifact *sourcev1.Artifact) {
	if artifact.Path == "" {
		return
	}
	format := "http://%s/%s"
	if strings.HasPrefix(s.Hostname, "http://") || strings.HasPrefix(s.Hostname, "https://") {
		format = "%s/%s"
	}
	artifact.URL = fmt.Sprintf(format, s.Hostname, strings.TrimLeft(artifact.Path, "/"))
}

// SetHostname sets the hostname of the given URL string to the current Storage.Hostname and returns the result.
func (s Storage) SetHostname(URL string) string {
	u, err := url.Parse(URL)
	if err != nil {
		return ""
	}
	u.Host = s.Hostname
	return u.String()
}

// MkdirAll calls os.MkdirAll for the given v1beta1.Artifact base dir.
func (s *Storage) MkdirAll(artifact sourcev1.Artifact) error {
	dir := filepath.Dir(s.LocalPath(artifact))
	return os.MkdirAll(dir, 0777)
}

// RemoveAll calls os.RemoveAll for the given v1beta1.Artifact base dir.
func (s *Storage) RemoveAll(artifact sourcev1.Artifact) error {
	dir := filepath.Dir(s.LocalPath(artifact))
	return os.RemoveAll(dir)
}

// RemoveAllButCurrent removes all files for the given v1beta1.Artifact base dir, excluding the current one.
func (s *Storage) RemoveAllButCurrent(artifact sourcev1.Artifact) error {
	localPath := s.LocalPath(artifact)
	dir := filepath.Dir(localPath)
	var errors []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			errors = append(errors, err.Error())
			return nil
		}

		if path != localPath && !info.IsDir() && info.Mode()&os.ModeSymlink != os.ModeSymlink {
			if err := os.Remove(path); err != nil {
				errors = append(errors, info.Name())
			}
		}
		return nil
	})

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove files: %s", strings.Join(errors, " "))
	}
	return nil
}

// ArtifactExist returns a boolean indicating whether the v1beta1.Artifact exists in storage and is a regular file.
func (s *Storage) ArtifactExist(artifact sourcev1.Artifact) bool {
	fi, err := os.Lstat(s.LocalPath(artifact))
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

// ArchiveFileFilter must return true if a file should not be included in the archive after inspecting the given path
// and/or os.FileInfo.
type ArchiveFileFilter func(p string, fi os.FileInfo) bool

// SourceIgnoreFilter returns an ArchiveFileFilter that filters out files matching sourceignore.VCSPatterns and any of
// the provided patterns.
// If an empty gitignore.Pattern slice is given, the matcher is set to sourceignore.NewDefaultMatcher.
func SourceIgnoreFilter(ps []gitignore.Pattern, domain []string) ArchiveFileFilter {
	matcher := sourceignore.NewDefaultMatcher(ps, domain)
	if len(ps) > 0 {
		ps = append(sourceignore.VCSPatterns(domain), ps...)
		matcher = sourceignore.NewMatcher(ps)
	}
	return func(p string, fi os.FileInfo) bool {
		// The directory is always false as the archiver does already skip
		// directories.
		return matcher.Match(strings.Split(p, string(filepath.Separator)), false)
	}
}

// Archive atomically archives the given directory as a tarball to the given v1beta1.Artifact path, excluding
// directories and any ArchiveFileFilter matches. While archiving, any environment specific data (for example,
// the user and group name) is stripped from file headers.
// If successful, it sets the checksum and last update time on the artifact.
func (s *Storage) Archive(artifact *sourcev1.Artifact, dir string, filter ArchiveFileFilter) (err error) {
	if f, err := os.Stat(dir); os.IsNotExist(err) || !f.IsDir() {
		return fmt.Errorf("invalid dir path: %s", dir)
	}

	localPath := s.LocalPath(*artifact)
	tf, err := os.CreateTemp(filepath.Split(localPath))
	if err != nil {
		return err
	}
	tmpName := tf.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpName)
		}
	}()

	h := newHash()
	mw := io.MultiWriter(h, tf)

	gw := gzip.NewWriter(mw)
	tw := tar.NewWriter(gw)
	if err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignore anything that is not a file (directories, symlinks)
		if !fi.Mode().IsRegular() {
			return nil
		}

		// Skip filtered files
		if filter != nil && filter(p, fi) {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, p)
		if err != nil {
			return err
		}
		// The name needs to be modified to maintain directory structure
		// as tar.FileInfoHeader only has access to the base name of the file.
		// Ref: https://golang.org/src/archive/tar/common.go?#L626
		relFilePath := p
		if filepath.IsAbs(dir) {
			relFilePath, err = filepath.Rel(dir, p)
			if err != nil {
				return err
			}
		}
		header.Name = relFilePath

		// We want to remove any environment specific data as well, this
		// ensures the checksum is purely content based.
		header.Gid = 0
		header.Uid = 0
		header.Uname = ""
		header.Gname = ""
		header.ModTime = time.Time{}
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(p)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := io.Copy(tw, f); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}); err != nil {
		tw.Close()
		gw.Close()
		tf.Close()
		return err
	}

	if err := tw.Close(); err != nil {
		gw.Close()
		tf.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}

	if err := fs.RenameWithFallback(tmpName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	return nil
}

// AtomicWriteFile atomically writes the io.Reader contents to the v1beta1.Artifact path.
// If successful, it sets the checksum and last update time on the artifact.
func (s *Storage) AtomicWriteFile(artifact *sourcev1.Artifact, reader io.Reader, mode os.FileMode) (err error) {
	localPath := s.LocalPath(*artifact)
	tf, err := os.CreateTemp(filepath.Split(localPath))
	if err != nil {
		return err
	}
	tfName := tf.Name()
	defer func() {
		if err != nil {
			os.Remove(tfName)
		}
	}()

	h := newHash()
	mw := io.MultiWriter(h, tf)

	if _, err := io.Copy(mw, reader); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tfName, mode); err != nil {
		return err
	}

	if err := fs.RenameWithFallback(tfName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	return nil
}

// Copy atomically copies the io.Reader contents to the v1beta1.Artifact path.
// If successful, it sets the checksum and last update time on the artifact.
func (s *Storage) Copy(artifact *sourcev1.Artifact, reader io.Reader) (err error) {
	localPath := s.LocalPath(*artifact)
	tf, err := os.CreateTemp(filepath.Split(localPath))
	if err != nil {
		return err
	}
	tfName := tf.Name()
	defer func() {
		if err != nil {
			os.Remove(tfName)
		}
	}()

	h := newHash()
	mw := io.MultiWriter(h, tf)

	if _, err := io.Copy(mw, reader); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}

	if err := fs.RenameWithFallback(tfName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	return nil
}

// CopyFromPath atomically copies the contents of the given path to the path of the v1beta1.Artifact.
// If successful, the checksum and last update time on the artifact is set.
func (s *Storage) CopyFromPath(artifact *sourcev1.Artifact, path string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Copy(artifact, f)
}

// CopyToPath copies the contents in the (sub)path of the given artifact to the given path.
func (s *Storage) CopyToPath(artifact *sourcev1.Artifact, subPath, toPath string) error {
	// create a tmp directory to store artifact
	tmp, err := os.MkdirTemp("", "flux-include-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	// read artifact file content
	localPath := s.LocalPath(*artifact)
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// untar the artifact
	untarPath := filepath.Join(tmp, "unpack")
	if _, err = untar.Untar(f, untarPath); err != nil {
		return err
	}

	// create the destination parent dir
	if err = os.MkdirAll(filepath.Dir(toPath), os.ModePerm); err != nil {
		return err
	}

	// copy the artifact content to the destination dir
	fromPath, err := securejoin.SecureJoin(untarPath, subPath)
	if err != nil {
		return err
	}
	if err := fs.RenameWithFallback(fromPath, toPath); err != nil {
		return err
	}
	return nil
}

// Symlink creates or updates a symbolic link for the given v1beta1.Artifact and returns the URL for the symlink.
func (s *Storage) Symlink(artifact sourcev1.Artifact, linkName string) (string, error) {
	localPath := s.LocalPath(artifact)
	dir := filepath.Dir(localPath)
	link := filepath.Join(dir, linkName)
	tmpLink := link + ".tmp"

	if err := os.Remove(tmpLink); err != nil && !os.IsNotExist(err) {
		return "", err
	}

	if err := os.Symlink(localPath, tmpLink); err != nil {
		return "", err
	}

	if err := os.Rename(tmpLink, link); err != nil {
		return "", err
	}

	url := fmt.Sprintf("http://%s/%s", s.Hostname, filepath.Join(filepath.Dir(artifact.Path), linkName))
	return url, nil
}

// Checksum returns the SHA256 checksum for the data of the given io.Reader as a string.
func (s *Storage) Checksum(reader io.Reader) string {
	h := newHash()
	_, _ = io.Copy(h, reader)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Lock creates a file lock for the given v1beta1.Artifact.
func (s *Storage) Lock(artifact sourcev1.Artifact) (unlock func(), err error) {
	lockFile := s.LocalPath(artifact) + ".lock"
	mutex := lockedfile.MutexAt(lockFile)
	return mutex.Lock()
}

// LocalPath returns the secure local path of the given artifact (that is: relative to the Storage.BasePath).
func (s *Storage) LocalPath(artifact sourcev1.Artifact) string {
	if artifact.Path == "" {
		return ""
	}
	path, err := securejoin.SecureJoin(s.BasePath, artifact.Path)
	if err != nil {
		return ""
	}
	return path
}

// newHash returns a new SHA256 hash.
func newHash() hash.Hash {
	return sha256.New()
}
