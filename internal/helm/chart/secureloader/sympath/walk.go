/*
Copyright (c) for portions of walk.go are held by The Go Authors, 2009 and are
provided under the BSD license.

https://github.com/golang/go/blob/master/LICENSE

Copyright The Helm Authors.
Copyright The Flux authors
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

package sympath

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// AbsWalkFunc functions like filepath.WalkFunc but provides the absolute path
// of fs.FileInfo when path is a symlink.
type AbsWalkFunc func(path, absPath string, info fs.FileInfo, err error) error

// Walk walks the file tree rooted at root, calling walkFn for each file or directory
// in the tree, including root. All errors that arise visiting files and directories
// are filtered by walkFn. The files are walked in lexical order, which makes the
// output deterministic but means that for very large directories Walk can be
// inefficient. Walk follows symbolic links.
func Walk(root string, walkFn AbsWalkFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		err = walkFn(root, root, nil, err)
	} else {
		err = symwalk(root, root, info, walkFn)
	}
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// readDirNames reads the directory named by dirname and returns
// a sorted list of directory entries.
func readDirNames(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// symwalk recursively descends path, calling AbsWalkFunc.
func symwalk(path, absPath string, info os.FileInfo, walkFn AbsWalkFunc) error {
	// Recursively walk symlinked directories.
	if IsSymlink(info) {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("error evaluating symlink %s: %w", path, err)
		}
		if info, err = os.Lstat(resolved); err != nil {
			return err
		}
		// NB: pass-on resolved as absolute path
		if err := symwalk(path, resolved, info, walkFn); err != nil && err != filepath.SkipDir {
			return err
		}
		return nil
	}

	if err := walkFn(path, absPath, info, nil); err != nil {
		return err
	}

	if !info.IsDir() {
		return nil
	}

	names, err := readDirNames(path)
	if err != nil {
		return walkFn(path, absPath, info, err)
	}

	for _, name := range names {
		filename := filepath.Join(path, name)
		// NB: possibly absPath != path separately
		absFilename := filepath.Join(absPath, name)
		fileInfo, err := os.Lstat(filename)
		if err != nil {
			if err := walkFn(filename, absFilename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			if err = symwalk(filename, absFilename, fileInfo, walkFn); err != nil {
				if (!fileInfo.IsDir() && !IsSymlink(fileInfo)) || err != filepath.SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

// IsSymlink is used to determine if the fileinfo is a symbolic link.
func IsSymlink(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSymlink != 0
}
