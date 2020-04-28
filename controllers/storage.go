/*
Copyright 2020 The Flux CD contributors.

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
	"context"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/lockedfile"
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

// NewStorage creates the storage helper for a given path and hostname
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

// ArtifactFor returns an artifact for the given Kubernetes object
func (s *Storage) ArtifactFor(kind string, metadata metav1.Object, fileName, revision string) sourcev1.Artifact {
	kind = strings.ToLower(kind)
	path := sourcev1.ArtifactPath(kind, metadata.GetNamespace(), metadata.GetName(), fileName)
	localPath := filepath.Join(s.BasePath, path)
	url := fmt.Sprintf("http://%s/%s", s.Hostname, path)

	return sourcev1.Artifact{
		Path:           localPath,
		URL:            url,
		Revision:       revision,
		LastUpdateTime: metav1.Now(),
	}
}

// MkdirAll calls os.MkdirAll for the given artifact base dir
func (s *Storage) MkdirAll(artifact sourcev1.Artifact) error {
	dir := filepath.Dir(artifact.Path)
	return os.MkdirAll(dir, 0777)
}

// RemoveAll calls os.RemoveAll for the given artifact base dir
func (s *Storage) RemoveAll(artifact sourcev1.Artifact) error {
	dir := filepath.Dir(artifact.Path)
	return os.RemoveAll(dir)
}

// RemoveAllButCurrent removes all files for the given artifact base dir excluding the current one
func (s *Storage) RemoveAllButCurrent(artifact sourcev1.Artifact) error {
	dir := filepath.Dir(artifact.Path)
	errors := []string{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if path != artifact.Path && !info.IsDir() && info.Mode()&os.ModeSymlink != os.ModeSymlink {
			if err := os.Remove(path); err != nil {
				errors = append(errors, info.Name())
			}
		}
		return nil
	})

	if len(errors) > 0 {
		return fmt.Errorf("faild to remove files: %s", strings.Join(errors, " "))
	}
	return nil
}

// ArtifactExist returns a boolean indicating whether the artifact file exists in storage
func (s *Storage) ArtifactExist(artifact sourcev1.Artifact) bool {
	if _, err := os.Stat(artifact.Path); os.IsNotExist(err) {
		return false
	}
	return true
}

// Archive creates a tar.gz to the artifact path from the given dir excluding the provided file extensions
func (s *Storage) Archive(artifact sourcev1.Artifact, dir string, excludes string, integrityCheck bool) error {
	if excludes == "" {
		excludes = "jpg,jpeg,gif,png,wmv,flv,tar.gz,zip"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	tarExcludes := fmt.Sprintf("--exclude=\\*.{%s} --exclude .git", excludes)
	cmd := fmt.Sprintf("cd %s && tar -c %s -f - . | gzip > %s", dir, tarExcludes, artifact.Path)
	command := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)

	err := command.Run()
	if err != nil {
		return fmt.Errorf("command '%s' failed: %w", cmd, err)
	}

	if integrityCheck {
		cmd = fmt.Sprintf("gunzip -t %s", artifact.Path)
		command = exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
		err = command.Run()
		if err != nil {
			return fmt.Errorf("gzip integrity check failed")
		}

		cmd = fmt.Sprintf("tar -tzf %s >/dev/null", artifact.Path)
		command = exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
		err = command.Run()
		if err != nil {
			return fmt.Errorf("tar integrity check failed")
		}
	}

	return nil
}

// WriteFile writes the given bytes to the artifact path if the checksum differs
func (s *Storage) WriteFile(artifact sourcev1.Artifact, data []byte) error {
	sum := s.Checksum(data)
	if file, err := os.Stat(artifact.Path); !os.IsNotExist(err) && !file.IsDir() {
		if fb, err := ioutil.ReadFile(artifact.Path); err == nil && sum == s.Checksum(fb) {
			return nil
		}
	}

	return ioutil.WriteFile(artifact.Path, data, 0644)
}

// Symlink creates or updates a symbolic link for the given artifact
// and returns the URL for the symlink
func (s *Storage) Symlink(artifact sourcev1.Artifact, linkName string) (string, error) {
	dir := filepath.Dir(artifact.Path)
	link := filepath.Join(dir, linkName)
	tmpLink := link + ".tmp"

	if err := os.Remove(tmpLink); err != nil && !os.IsNotExist(err) {
		return "", err
	}

	if err := os.Symlink(artifact.Path, tmpLink); err != nil {
		return "", err
	}

	if err := os.Rename(tmpLink, link); err != nil {
		return "", err
	}

	parts := strings.Split(artifact.URL, "/")
	url := strings.Replace(artifact.URL, parts[len(parts)-1], linkName, 1)
	return url, nil
}

// Checksum returns the SHA1 checksum for the given bytes as a string
func (s *Storage) Checksum(b []byte) string {
	return fmt.Sprintf("%x", sha1.Sum(b))
}

// Lock creates a file lock for the given artifact
func (s *Storage) Lock(artifact sourcev1.Artifact) (unlock func(), err error) {
	lockFile := artifact.Path + ".lock"
	mutex := lockedfile.MutexAt(lockFile)
	return mutex.Lock()
}
