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
)

// TransportOptions represents options to be applied at transport-level
// at request time.
type TransportOptions struct {
	TargetURL string
	CABundle  []byte
}

var (
	transportOpts = make(map[string]TransportOptions, 0)
	m             sync.RWMutex
)

func AddTransportOptions(targetUrl string, opts TransportOptions) {
	m.Lock()
	transportOpts[targetUrl] = opts
	m.Unlock()
}

func RemoveTransportOptions(targetUrl string) {
	m.Lock()
	delete(transportOpts, targetUrl)
	m.Unlock()
}

func transportOptions(targetUrl string) (*TransportOptions, bool) {
	m.RLock()
	opts, found := transportOpts[targetUrl]
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
func EffectiveURL(targetUrl string) string {
	if !Enabled() {
		return targetUrl
	}

	if opts, found := transportOptions(targetUrl); found {
		if opts.TargetURL != "" {
			return opts.TargetURL
		}
	}

	return targetUrl
}
