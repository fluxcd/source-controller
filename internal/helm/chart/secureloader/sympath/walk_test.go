/*
Copyright (c) for portions of walk_test.go are held by The Go Authors, 2009 and are
provided under the BSD license.

https://github.com/golang/go/blob/master/LICENSE

Copyright The Helm Authors.
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
	"os"
	"path/filepath"
	"testing"
)

type Node struct {
	name            string
	entries         []*Node // nil if the entry is a file
	marks           int
	expectedMarks   int
	symLinkedTo     string
	absPath         string
	expectedAbsPath string
}

var tree = &Node{
	"testdata",
	[]*Node{
		{"a", nil, 0, 1, "", "", "testdata/a"},
		{"b", []*Node{}, 0, 1, "", "", "testdata/b"},
		{"c", nil, 0, 2, "", "", "testdata/c"},
		{"d", nil, 0, 0, "c", "", "testdata/c"},
		{
			"e",
			[]*Node{
				{"x", nil, 0, 1, "", "", "testdata/e/x"},
				{"y", []*Node{}, 0, 1, "", "", "testdata/e/y"},
				{
					"z",
					[]*Node{
						{"u", nil, 0, 1, "", "", "testdata/e/z/u"},
						{"v", nil, 0, 1, "", "", "testdata/e/z/v"},
						{"w", nil, 0, 1, "", "", "testdata/e/z/w"},
					},
					0,
					1,
					"", "", "testdata/e/z",
				},
			},
			0,
			1,
			"", "", "testdata/e",
		},
	},
	0,
	1,
	"", "", "testdata",
}

func walkTree(n *Node, path string, f func(path string, n *Node)) {
	f(path, n)
	for _, e := range n.entries {
		walkTree(e, filepath.Join(path, e.name), f)
	}
}

func makeTree(t *testing.T) {
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.entries == nil {
			if n.symLinkedTo != "" {
				if err := os.Symlink(n.symLinkedTo, path); err != nil {
					t.Fatalf("makeTree: %v", err)
				}
			} else {
				fd, err := os.Create(path)
				if err != nil {
					t.Fatalf("makeTree: %v", err)
					return
				}
				fd.Close()
			}
		} else {
			if err := os.Mkdir(path, 0770); err != nil {
				t.Fatalf("makeTree: %v", err)
			}
		}
	})
}

func checkMarks(t *testing.T, report bool) {
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.marks != n.expectedMarks && report {
			t.Errorf("node %s mark = %d; expected %d", path, n.marks, n.expectedMarks)
		}
		if n.absPath != n.expectedAbsPath && report {
			t.Errorf("node %s absPath = %s; expected %s", path, n.absPath, n.expectedAbsPath)
		}
		n.marks = 0
	})
}

// Assumes that each node name is unique. Good enough for a test.
// If clear is true, any incoming error is cleared before return. The errors
// are always accumulated, though.
func mark(absPath string, info os.FileInfo, err error, errors *[]error, clear bool) error {
	if err != nil {
		*errors = append(*errors, err)
		if clear {
			return nil
		}
		return err
	}
	name := info.Name()
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.symLinkedTo == name {
			n.absPath = absPath
		}
		if n.name == name {
			n.marks++
			n.absPath = absPath
		}
	})
	return nil
}

func TestWalk(t *testing.T) {
	makeTree(t)
	errors := make([]error, 0, 10)
	clear := true
	markFn := func(path, absPath string, info os.FileInfo, err error) error {
		return mark(absPath, info, err, &errors, clear)
	}
	// Expect no errors.
	err := Walk(tree.name, markFn)
	if err != nil {
		t.Fatalf("no error expected, found: %s", err)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected errors: %s", errors)
	}
	checkMarks(t, true)

	// cleanup
	if err := os.RemoveAll(tree.name); err != nil {
		t.Errorf("removeTree: %v", err)
	}
}
