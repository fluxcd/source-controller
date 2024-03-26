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

package common

import "strings"

// StringResource is there to satisfy the github.com/google/go-containerregistry/pkg/authn.Resource interface.
// It merely wraps a given string and returns it for all of the interface's methods.
type StringResource struct {
	Registry string
}

// String returns a string representation of the StringResource.
// It converts the StringResource object to a string.
// The returned string contains the value of the StringResource.
func (r StringResource) String() string {
	return r.Registry
}

// RegistryStr returns the string representation of the registry resource.
// It converts the StringResource object to a string that represents the registry resource.
// The returned string can be used to interact with the registry resource.
func (r StringResource) RegistryStr() string {
	return strings.Split(r.Registry, "/")[0]
}
