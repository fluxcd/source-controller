/*
Copyright 2024 The Flux authors

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

package testproxy

import (
	"net/http"
	"testing"

	"github.com/elazarl/goproxy"

	testlistener "github.com/werf/nelm-source-controller/tests/listener"
)

// New creates a new goproxy server on a random port and returns
// the address and the port of this server. It also registers a
// cleanup functions to close the server and the listener when
// the test ends.
func New(t *testing.T) (string, int) {
	t.Helper()

	lis, addr, port := testlistener.New(t)

	handler := goproxy.NewProxyHttpServer()
	handler.Verbose = true

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	go server.Serve(lis)
	t.Cleanup(func() { server.Close() })

	return addr, port
}
