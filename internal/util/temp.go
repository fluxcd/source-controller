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

package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TempDirForObj creates a new temporary directory in the directory dir
// in the format of 'Kind-Namespace-Name-*', and returns the
// pathname of the new directory.
func TempDirForObj(dir string, obj client.Object) (string, error) {
	return os.MkdirTemp(dir, pattern(obj))
}

// TempPathForObj creates a temporary file path in the format of
// '<dir>/Kind-Namespace-Name-<random bytes><suffix>'.
// If the given dir is empty, os.TempDir is used as a default.
func TempPathForObj(dir, suffix string, obj client.Object) string {
	if dir == "" {
		dir = os.TempDir()
	}
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(dir, pattern(obj)+hex.EncodeToString(randBytes)+suffix)
}

func pattern(obj client.Object) (p string) {
	kind := strings.ToLower(obj.GetObjectKind().GroupVersionKind().Kind)
	return fmt.Sprintf("%s-%s-%s-", kind, obj.GetNamespace(), obj.GetName())
}
