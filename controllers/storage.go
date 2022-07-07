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
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/lockedfile"
	"github.com/fluxcd/pkg/untar"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	sourcefs "github.com/fluxcd/source-controller/internal/fs"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

const GarbageCountLimit = 1000

// Storage manages artifacts
type Storage struct {
	// BasePath is the local directory path where the source artifacts are stored.
	BasePath string `json:"basePath"`

	// Hostname is the file server host name used to compose the artifacts URIs.
	Hostname string `json:"hostname"`

	// ArtifactRetentionTTL is the duration of time that artifacts will be kept
	// in storage before being garbage collected.
	ArtifactRetentionTTL time.Duration `json:"artifactRetentionTTL"`

	// ArtifactRetentionRecords is the maximum number of artifacts to be kept in
	// storage after a garbage collection.
	ArtifactRetentionRecords int `json:"artifactRetentionRecords"`
}

// NewStorage creates the storage helper for a given path and hostname.
func NewStorage(basePath string, hostname string, artifactRetentionTTL time.Duration, artifactRetentionRecords int) (*Storage, error) {
	if f, err := os.Stat(basePath); os.IsNotExist(err) || !f.IsDir() {
		return nil, fmt.Errorf("invalid dir path: %s", basePath)
	}
	return &Storage{
		BasePath:                 basePath,
		Hostname:                 hostname,
		ArtifactRetentionTTL:     artifactRetentionTTL,
		ArtifactRetentionRecords: artifactRetentionRecords,
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
	return os.MkdirAll(dir, 0o700)
}

// RemoveAll calls os.RemoveAll for the given v1beta1.Artifact base dir.
func (s *Storage) RemoveAll(artifact sourcev1.Artifact) (string, error) {
	var deletedDir string
	dir := filepath.Dir(s.LocalPath(artifact))
	// Check if the dir exists.
	_, err := os.Stat(dir)
	if err == nil {
		deletedDir = dir
	}
	return deletedDir, os.RemoveAll(dir)
}

// RemoveAllButCurrent removes all files for the given v1beta1.Artifact base dir, excluding the current one.
func (s *Storage) RemoveAllButCurrent(artifact sourcev1.Artifact) ([]string, error) {
	deletedFiles := []string{}
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
			} else {
				// Collect the successfully deleted file paths.
				deletedFiles = append(deletedFiles, path)
			}
		}
		return nil
	})

	if len(errors) > 0 {
		return deletedFiles, fmt.Errorf("failed to remove files: %s", strings.Join(errors, " "))
	}
	return deletedFiles, nil
}

// getGarbageFiles returns all files that need to be garbage collected for the given artifact.
// Garbage files are determined based on the below flow:
// 1. collect all files with an expired ttl
// 2. if we satisfy maxItemsToBeRetained, then return
// 3. else, remove all files till the latest n files remain, where n=maxItemsToBeRetained
func (s *Storage) getGarbageFiles(artifact sourcev1.Artifact, totalCountLimit, maxItemsToBeRetained int, ttl time.Duration) ([]string, error) {
	localPath := s.LocalPath(artifact)
	dir := filepath.Dir(localPath)
	garbageFiles := []string{}
	filesWithCreatedTs := make(map[time.Time]string)
	// sortedPaths contain all files sorted according to their created ts.
	sortedPaths := []string{}
	now := time.Now().UTC()
	totalFiles := 0
	var errors []string
	creationTimestamps := []time.Time{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errors = append(errors, err.Error())
			return nil
		}
		if totalFiles >= totalCountLimit {
			return fmt.Errorf("reached file walking limit, already walked over: %d", totalFiles)
		}
		info, err := d.Info()
		if err != nil {
			errors = append(errors, err.Error())
			return nil
		}
		createdAt := info.ModTime().UTC()
		diff := now.Sub(createdAt)
		// Compare the time difference between now and the time at which the file was created
		// with the provided TTL. Delete if the difference is greater than the TTL.
		expired := diff > ttl
		if !info.IsDir() && info.Mode()&os.ModeSymlink != os.ModeSymlink {
			if path != localPath && expired {
				garbageFiles = append(garbageFiles, path)
			}
			totalFiles += 1
			filesWithCreatedTs[createdAt] = path
			creationTimestamps = append(creationTimestamps, createdAt)
		}
		return nil

	})
	if len(errors) > 0 {
		return nil, fmt.Errorf("can't walk over file: %s", strings.Join(errors, ","))
	}

	// We already collected enough garbage files to satisfy the no. of max
	// items that are supposed to be retained, so exit early.
	if totalFiles-len(garbageFiles) < maxItemsToBeRetained {
		return garbageFiles, nil
	}

	// sort all timestamps in an ascending order.
	sort.Slice(creationTimestamps, func(i, j int) bool { return creationTimestamps[i].Before(creationTimestamps[j]) })
	for _, ts := range creationTimestamps {
		path, ok := filesWithCreatedTs[ts]
		if !ok {
			return garbageFiles, fmt.Errorf("failed to fetch file for created ts: %v", ts)
		}
		sortedPaths = append(sortedPaths, path)
	}

	var collected int
	noOfGarbageFiles := len(garbageFiles)
	for _, path := range sortedPaths {
		if path != localPath && !stringInSlice(path, garbageFiles) {
			// If we previously collected a few garbage files with an expired ttl, then take that into account
			// when checking whether we need to remove more files to satisfy the max no. of items allowed
			// in the filesystem, along with the no. of files already removed in this loop.
			if noOfGarbageFiles > 0 {
				if (len(sortedPaths) - collected - len(garbageFiles)) > maxItemsToBeRetained {
					garbageFiles = append(garbageFiles, path)
					collected += 1
				}
			} else {
				if len(sortedPaths)-collected > maxItemsToBeRetained {
					garbageFiles = append(garbageFiles, path)
					collected += 1
				}
			}
		}
	}

	return garbageFiles, nil
}

// GarbageCollect removes all garabge files in the artifact dir according to the provided
// retention options.
func (s *Storage) GarbageCollect(ctx context.Context, artifact sourcev1.Artifact, timeout time.Duration) ([]string, error) {
	delFilesChan := make(chan []string)
	errChan := make(chan error)
	// Abort if it takes more than the provided timeout duration.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	go func() {
		garbageFiles, err := s.getGarbageFiles(artifact, GarbageCountLimit, s.ArtifactRetentionRecords, s.ArtifactRetentionTTL)
		if err != nil {
			errChan <- err
			return
		}
		var errors []error
		var deleted []string
		if len(garbageFiles) > 0 {
			for _, file := range garbageFiles {
				err := os.Remove(file)
				if err != nil {
					errors = append(errors, err)
				} else {
					deleted = append(deleted, file)
				}
			}
		}
		if len(errors) > 0 {
			errChan <- kerrors.NewAggregate(errors)
			return
		}
		delFilesChan <- deleted
	}()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case delFiles := <-delFilesChan:
			return delFiles, nil
		case err := <-errChan:
			return nil, err
		}
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
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
		return matcher.Match(strings.Split(p, string(filepath.Separator)), fi.IsDir())
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
	sz := &writeCounter{}
	mw := io.MultiWriter(h, tf, sz)

	gw := gzip.NewWriter(mw)
	tw := tar.NewWriter(gw)
	if err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignore anything that is not a file or directories e.g. symlinks
		if m := fi.Mode(); !(m.IsRegular() || m.IsDir()) {
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

		if !fi.Mode().IsRegular() {
			return nil
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

	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}

	if err := sourcefs.RenameWithFallback(tmpName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	artifact.Size = &sz.written

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
	sz := &writeCounter{}
	mw := io.MultiWriter(h, tf, sz)

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

	if err := sourcefs.RenameWithFallback(tfName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	artifact.Size = &sz.written

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
	sz := &writeCounter{}
	mw := io.MultiWriter(h, tf, sz)

	if _, err := io.Copy(mw, reader); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}

	if err := sourcefs.RenameWithFallback(tfName, localPath); err != nil {
		return err
	}

	artifact.Checksum = fmt.Sprintf("%x", h.Sum(nil))
	artifact.LastUpdateTime = metav1.Now()
	artifact.Size = &sz.written

	return nil
}

// CopyFromPath atomically copies the contents of the given path to the path of the v1beta1.Artifact.
// If successful, the checksum and last update time on the artifact is set.
func (s *Storage) CopyFromPath(artifact *sourcev1.Artifact, path string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	err = s.Copy(artifact, f)
	return err
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
	if err := sourcefs.RenameWithFallback(fromPath, toPath); err != nil {
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

// writecounter is an implementation of io.Writer that only records the number
// of bytes written.
type writeCounter struct {
	written int64
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.written += int64(n)
	return n, nil
}
