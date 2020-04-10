package controllers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// Artifact represents the output of a source synchronisation
type Artifact struct {
	// Path is the local file path of this artifact
	Path string `json:"path"`

	// URL is the HTTP address of this artifact
	URL string `json:"url"`
}

// NewStorage creates the storage helper for a given path and hostname
func NewStorage(basePath string, hostname string, timeout time.Duration) (*Storage, error) {
	if f, err := os.Stat(basePath); os.IsNotExist(err) || !f.IsDir() {
		return nil, fmt.Errorf("invalid dir path %s", basePath)
	}

	return &Storage{
		BasePath: basePath,
		Hostname: hostname,
		Timeout:  timeout,
	}, nil
}

// ArtifactFor returns an artifact for the given Kubernetes object
func (s *Storage) ArtifactFor(kind string, metadata metav1.Object, fileName string) Artifact {
	path := fmt.Sprintf("%s/%s-%s/%s", kind, metadata.GetName(), metadata.GetNamespace(), fileName)
	localPath := filepath.Join(s.BasePath, path)
	url := fmt.Sprintf("http://%s/%s", s.Hostname, path)

	return Artifact{
		Path: localPath,
		URL:  url,
	}
}

// MkdirAll calls os.MkdirAll for the given artifact base dir
func (s *Storage) MkdirAll(artifact Artifact) error {
	dir := filepath.Dir(artifact.Path)
	return os.MkdirAll(dir, 0777)
}

// RemoveAll calls os.RemoveAll for the given artifact base dir
func (s *Storage) RemoveAll(artifact Artifact) error {
	dir := filepath.Dir(artifact.Path)
	return os.RemoveAll(dir)
}

// RemoveAllButCurrent removes all files for the given artifact base dir excluding the current one
func (s *Storage) RemoveAllButCurrent(artifact Artifact) error {
	dir := filepath.Dir(artifact.Path)
	errors := []string{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if path != artifact.Path {
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
func (s *Storage) ArtifactExist(artifact Artifact) bool {
	if _, err := os.Stat(artifact.Path); os.IsNotExist(err) {
		return false
	}
	return true
}

// Archive creates a tar.gz to the artifact path from the given dir excluding the provided file extensions
func (s *Storage) Archive(artifact Artifact, dir string, excludes string) error {
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
	return nil
}
