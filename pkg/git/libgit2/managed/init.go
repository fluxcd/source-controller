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

package managed

import (
	"sync"
	"time"

	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/go-logr/logr"
)

var (
	once sync.Once

	// sshConnectionTimeOut defines the timeout used for when
	// creating ssh.ClientConfig, which translates in the timeout
	// for stablishing the SSH TCP connections.
	sshConnectionTimeOut time.Duration = 30 * time.Second

	// fullHttpClientTimeOut defines the maximum amount of
	// time a http client may take before timing out,
	// regardless of the current operation (i.e. connection,
	// handshake, put/get).
	fullHttpClientTimeOut time.Duration = 10 * time.Minute

	debugLog logr.Logger
	traceLog logr.Logger
)

// InitManagedTransport initialises HTTP(S) and SSH managed transport
// for git2go, and therefore only impact git operations using the
// libgit2 implementation.
//
// This must run after git2go.init takes place, hence this is not executed
// within a init().
// Regardless of the state in libgit2/git2go, this will replace the
// built-in transports.
//
// This function will only register managed transports once, subsequent calls
// leads to no-op.
func InitManagedTransport(log logr.Logger) error {
	var err error

	once.Do(func() {
		log.Info("Enabling experimental managed transport")
		debugLog = log.V(logger.DebugLevel)
		traceLog = log.V(logger.TraceLevel)

		if err = registerManagedHTTP(); err != nil {
			return
		}

		err = registerManagedSSH()
	})

	return err
}
