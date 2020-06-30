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

package testserver

import (
	"io/ioutil"
	"net/http/httptest"
	"path/filepath"

	"github.com/sosedoff/gitkit"
)

// NewTempGitServer returns a GitServer with a newly created temp
// dir as repository docroot.
func NewTempGitServer() (*GitServer, error) {
	tmpDir, err := ioutil.TempDir("", "git-server-test-")
	if err != nil {
		return nil, err
	}
	srv := NewGitServer(tmpDir)
	return srv, nil
}

// NewGitServer returns a GitServer with the given repository docroot
// set.
func NewGitServer(docroot string) *GitServer {
	root, err := filepath.Abs(docroot)
	if err != nil {
		panic(err)
	}
	return &GitServer{
		config: gitkit.Config{Dir: root},
	}
}

// GitServer is a git server for testing purposes.
// It can serve git repositories over HTTP and SSH.
type GitServer struct {
	config     gitkit.Config
	httpServer *httptest.Server
	sshServer  *gitkit.SSH
}

// AutoCreate enables the automatic creation of a non-existing Git
// repository on push.
func (s *GitServer) AutoCreate() *GitServer {
	s.config.AutoCreate = true
	return s
}

// StartHTTP starts a new HTTP git server with the current configuration.
func (s *GitServer) StartHTTP() error {
	s.StopHTTP()
	service := gitkit.New(s.config)
	if err := service.Setup(); err != nil {
		return err
	}
	s.httpServer = httptest.NewServer(service)
	return nil
}

// StopHTTP stops the HTTP git server.
func (s *GitServer) StopHTTP() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	return
}

// StartSSH starts a new SSH git server with the current configuration.
func (s *GitServer) StartSSH() error {
	_ = s.StopSSH()
	s.sshServer = gitkit.NewSSH(s.config)
	// :0 should result in an OS assigned free port
	return s.sshServer.ListenAndServe(":0")
}

// StopSSH stops the SSH git server.
func (s *GitServer) StopSSH() error {
	if s.sshServer != nil {
		return s.sshServer.Stop()
	}
	return nil
}

// Root returns the repositories root directory.
func (s *GitServer) Root() string {
	return s.config.Dir
}

// HTTPAddress returns the address of the HTTP git server.
func (s *GitServer) HTTPAddress() string {
	if s.httpServer != nil {
		return s.httpServer.URL
	}
	return ""
}

// SSHAddress returns the address of the SSH git server.
func (s *GitServer) SSHAddress() string {
	if s.sshServer != nil {
		return s.sshServer.Address()
	}
	return ""
}
