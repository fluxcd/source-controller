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
	"context"
	"sync"

	"github.com/fluxcd/source-controller/pkg/git"
	git2go "github.com/libgit2/git2go/v33"
)

// TransportOptions represents options to be applied at transport-level
// at request time.
type TransportOptions struct {
	TargetURL    string
	AuthOpts     *git.AuthOptions
	ProxyOptions *git2go.ProxyOptions
	Context      context.Context
}

var (
	// transportOpts maps a unique URL to a set of transport options.
	transportOpts = make(map[string]TransportOptions, 0)
	m             sync.RWMutex
)

// AddTransportOptions registers a TransportOptions object mapped to the
// provided transportOptsURL, which must be a valid URL, i.e. prefixed with "http://"
// or "ssh://", as it is used as a dummy URL for all git operations and the managed
// transports will only be invoked for the protocols that they have been
// registered for.
func AddTransportOptions(transportOptsURL string, opts TransportOptions) {
	m.Lock()
	transportOpts[transportOptsURL] = opts
	m.Unlock()
}

// RemoveTransportOptions removes the registerd TransportOptions object
// mapped to the provided id.
func RemoveTransportOptions(transportOptsURL string) {
	m.Lock()
	delete(transportOpts, transportOptsURL)
	m.Unlock()
}

func getTransportOptions(transportOptsURL string) (*TransportOptions, bool) {
	m.RLock()
	opts, found := transportOpts[transportOptsURL]
	m.RUnlock()

	if found {
		return &opts, true
	}
	return nil, false
}
