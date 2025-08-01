// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package fs

import (
	"fmt"
	"os"
	"syscall"
)

// renameFallback attempts to determine the appropriate fallback to failed rename
// operation depending on the resulting error.
func renameFallback(err error, src, dst string) error {
	// Rename may fail if src and dst are on different devices; fall back to
	// copy if we detect that case. syscall.EXDEV is the common name for the
	// cross device link error which has varying output text across different
	// operating systems.
	// Rename may also fail if the directory already exists, which occurs when
	// mapping to the root of another repo. Copy should still succeed.
	terr, ok := err.(*os.LinkError)
	if !ok {
		return err
	} else if terr.Err != syscall.EXDEV && terr.Err != syscall.EEXIST {
		return fmt.Errorf("link error: cannot rename %s to %s: %w", src, dst, terr)
	}

	return renameByCopy(src, dst)
}
