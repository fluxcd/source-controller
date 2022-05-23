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

	"github.com/fluxcd/source-controller/pkg/git"
)

// TransportOptions represents options to be applied at transport-level
// at request time.
type TransportOptions struct {
	TargetURL string
	AuthOpts  *git.AuthOptions
}

var (
	// transportOpts maps a unique id to a set of transport options.
	transportOpts = make(map[string]TransportOptions, 0)
	m             sync.RWMutex
)

func AddTransportOptions(id string, opts TransportOptions) {
	m.Lock()
	transportOpts[id] = opts
	m.Unlock()
}

func RemoveTransportOptions(id string) {
	m.Lock()
	delete(transportOpts, id)
	m.Unlock()
}

func getTransportOptions(id string) (*TransportOptions, bool) {
	m.RLock()
	opts, found := transportOpts[id]
	m.RUnlock()

	if found {
		return &opts, true
	}
	return nil, false
}

// EffectiveURL returns the effective URL for requests.
//
// Given that TransportOptions can allow for the target URL to be overriden
// this returns the same input if Managed Transport is disabled or if no TargetURL
// is set on TransportOptions.
func EffectiveURL(id string) string {
	if !Enabled() {
		return id
	}

	if opts, found := getTransportOptions(id); found {
		if opts.TargetURL != "" {
			return opts.TargetURL
		}
	}

	return id
}
