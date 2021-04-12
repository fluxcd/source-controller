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

package sourceignore

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

const (
	ExcludeFile  = ".sourceignore"
	ExcludeVCS   = ".git/,.gitignore,.gitmodules,.gitattributes"
	ExcludeExt   = "*.jpg,*.jpeg,*.gif,*.png,*.wmv,*.flv,*.tar.gz,*.zip"
	ExcludeCI    = ".github/,.circleci/,.travis.yml,.gitlab-ci.yml,appveyor.yml,.drone.yml,cloudbuild.yaml,codeship-services.yml,codeship-steps.yml"
	ExcludeExtra = "**/.goreleaser.yml,**/.sops.yaml,**/.flux.yaml"
)

// NewMatcher returns a gitignore.Matcher for the given gitignore.Pattern
// slice. It mainly exists to compliment the API.
func NewMatcher(ps []gitignore.Pattern) gitignore.Matcher {
	return gitignore.NewMatcher(ps)
}

// GetPatterns collects ignore patterns from the given reader and
// returns them as a gitignore.Pattern slice.
func GetPatterns(reader io.Reader, path []string) []gitignore.Pattern {
	var ps []gitignore.Pattern
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		s := scanner.Text()
		if !strings.HasPrefix(s, "#") && len(strings.TrimSpace(s)) > 0 {
			ps = append(ps, gitignore.ParsePattern(s, path))
		}
	}

	return ps
}

// LoadExcludePatterns loads the excluded patterns from .sourceignore or other
// sources and returns the gitignore.Pattern slice.
func LoadExcludePatterns(dir string, ignore *string) ([]gitignore.Pattern, error) {
	path := strings.Split(dir, "/")

	var ps []gitignore.Pattern
	for _, p := range strings.Split(ExcludeVCS, ",") {
		ps = append(ps, gitignore.ParsePattern(p, path))
	}

	if ignore == nil {
		all := strings.Join([]string{ExcludeExt, ExcludeCI, ExcludeExtra}, ",")
		for _, p := range strings.Split(all, ",") {
			ps = append(ps, gitignore.ParsePattern(p, path))
		}

		if f, err := os.Open(filepath.Join(dir, ExcludeFile)); err == nil {
			defer f.Close()
			ps = append(ps, GetPatterns(f, path)...)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		ps = append(ps, GetPatterns(bytes.NewBufferString(*ignore), path)...)
	}

	return ps, nil
}
