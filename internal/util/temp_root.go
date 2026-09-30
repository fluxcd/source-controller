/*
Copyright 2026 The Flux authors

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

package util

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// staleSuffix is appended to a temp root that a previous process left behind,
// when it is moved aside to be purged.
const staleSuffix = ".stale-"

// PrepareTempRoot gives the process an empty directory at root for its
// temporary files. Anything a previous process left in root, because it
// exited without running its deferred cleanup, is moved aside first. It
// returns the paths that hold leftovers, including those a previous purge
// did not finish, so that the caller can remove them with PurgeTempRoots.
// It must be called before the reconcilers start.
func PrepareTempRoot(root string) ([]string, error) {
	_, err := os.Lstat(root)
	switch {
	case err == nil:
		stale := fmt.Sprintf("%s%s%d", root, staleSuffix, time.Now().UnixNano())
		if err := os.Rename(root, stale); err != nil {
			return nil, fmt.Errorf("failed to move aside %s: %w", root, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to stat %s: %w", root, err)
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", root, err)
	}

	parent, base := filepath.Split(root)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", parent, err)
	}
	var stale []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), base+staleSuffix) {
			stale = append(stale, filepath.Join(parent, entry.Name()))
		}
	}
	return stale, nil
}

// PurgeTempRoots removes the given paths, logging every removal at info
// level and every failure at error level. It stops as soon as ctx is done
// and returns the number of paths that were removed.
func PurgeTempRoots(ctx context.Context, log logr.Logger, paths []string) int {
	purged := 0
	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			log.Error(err, "aborted purge of stale tmp dirs",
				"purged", purged, "remaining", len(paths)-i)
			return purged
		}
		if err := os.RemoveAll(path); err != nil {
			log.Error(err, "failed to remove stale tmp dir", "path", path)
			continue
		}
		log.Info("removed stale tmp dir", "path", path)
		purged++
	}
	return purged
}
