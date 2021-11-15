/*
Copyright 2021 The Flux authors

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

package getter

import (
	"bytes"

	"helm.sh/helm/v3/pkg/getter"
)

// MockGetter can be used as a simple mocking getter.Getter implementation.
type MockGetter struct {
	Response []byte

	requestedURL string
}

func (g *MockGetter) Get(u string, _ ...getter.Option) (*bytes.Buffer, error) {
	g.requestedURL = u
	r := g.Response
	return bytes.NewBuffer(r), nil
}

// LastGet returns the last requested URL for Get.
func (g *MockGetter) LastGet() string {
	return g.requestedURL
}
