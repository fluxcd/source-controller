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

package repository

import (
	"fmt"
	"net/url"
	"strings"

	helmreg "helm.sh/helm/v3/pkg/registry"
)

const (
	alias = "@"
)

var (
	// errInvalidDepURL is returned when the dependency URL is not supported
	errInvalidDepURL = fmt.Errorf("invalid dependency repository URL")
	// errInvalidAliasedDep is returned when the dependency URL is an alias
	errInvalidAliasedDep = fmt.Errorf("aliased repository dependency is not supported")
)

// NormalizeURL normalizes a ChartRepository URL by its scheme.
func NormalizeURL(repositoryURL string) (string, error) {
	if repositoryURL == "" {
		return "", nil
	}
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return "", err
	}

	if u.Scheme == helmreg.OCIScheme {
		u.Path = strings.TrimRight(u.Path, "/")
		// we perform the same operation on u.RawPath so that it will be a valid encoding
		// of u.Path. This allows u.EscapedPath() (which is used in computing u.String()) to return
		// the correct value when the path is url encoded.
		// ref: https://pkg.go.dev/net/url#URL.EscapedPath
		u.RawPath = strings.TrimRight(u.RawPath, "/")
		return u.String(), nil
	}

	u.Path = strings.TrimRight(u.Path, "/") + "/"
	u.RawPath = strings.TrimRight(u.RawPath, "/") + "/"
	return u.String(), nil
}

// ValidateDepURL returns an error if the given depended repository URL declaration is not supported
// The reason for this is that the dependency manager will not be able to resolve the alias declaration
// e.g. repository: "@fantastic-charts"
func ValidateDepURL(repositoryURL string) error {
	switch {
	case strings.HasPrefix(repositoryURL, helmreg.OCIScheme):
		return nil
	case strings.HasPrefix(repositoryURL, "https://") || strings.HasPrefix(repositoryURL, "http://"):
		return nil
	case strings.HasPrefix(repositoryURL, alias):
		return fmt.Errorf("%w: %s", errInvalidAliasedDep, repositoryURL)
	default:
		return fmt.Errorf("%w: %s", errInvalidDepURL, repositoryURL)
	}
}
