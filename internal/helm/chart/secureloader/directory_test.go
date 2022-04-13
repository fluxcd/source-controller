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

package secureloader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader/ignore"
)

func TestSecureDirLoader_Load(t *testing.T) {
	metadata := chart.Metadata{
		Name:       "test",
		APIVersion: "v2",
		Version:    "1.0",
		Type:       "application",
	}

	t.Run("chart", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		m := metadata
		b, err := yaml.Marshal(&m)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "Chart.yaml"), b, 0o640)).To(Succeed())

		got, err := (NewSecureDirLoader(tmpDir, "", helm.MaxChartFileSize)).Load()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).ToNot(BeNil())
		g.Expect(got.Name()).To(Equal(m.Name))
	})

	t.Run("chart with absolute path", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		m := metadata
		b, err := yaml.Marshal(&m)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "Chart.yaml"), b, 0o640)).To(Succeed())

		got, err := (NewSecureDirLoader(tmpDir, tmpDir, helm.MaxChartFileSize)).Load()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).ToNot(BeNil())
		g.Expect(got.Name()).To(Equal(m.Name))
	})

	t.Run("chart with illegal path", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()

		m := metadata
		b, err := yaml.Marshal(&m)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "Chart.yaml"), b, 0o640)).To(Succeed())

		root := filepath.Join(tmpDir, "root")
		g.Expect(os.Mkdir(root, 0o700)).To(Succeed())

		got, err := (NewSecureDirLoader(root, "../", helm.MaxChartFileSize)).Load()
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("failed to load chart from /: Chart.yaml file is missing"))
		g.Expect(got).To(BeNil())

		got, err = (NewSecureDirLoader(root, tmpDir, helm.MaxChartFileSize)).Load()
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("failed to load chart from /: Chart.yaml file is missing"))
		g.Expect(got).To(BeNil())
	})

	t.Run("chart with .helmignore", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		m := metadata
		b, err := yaml.Marshal(&m)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "Chart.yaml"), b, 0o640)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, ignore.HelmIgnore), []byte("file.txt"), 0o640)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("not included"), 0o640)).To(Succeed())

		got, err := (NewSecureDirLoader(tmpDir, "", helm.MaxChartFileSize)).Load()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).ToNot(BeNil())
		g.Expect(got.Name()).To(Equal(m.Name))
		g.Expect(got.Raw).To(HaveLen(2))
	})
}

func Test_secureLoadIgnoreRules(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		g := NewWithT(t)

		r, err := secureLoadIgnoreRules("/workdir", "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r.Ignore("file.txt", nil)).To(BeFalse())
		g.Expect(r.Ignore("templates/.dotfile", nil)).To(BeTrue())
	})

	t.Run("with "+ignore.HelmIgnore, func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		g.Expect(os.WriteFile(filepath.Join(tmpDir, ignore.HelmIgnore), []byte("file.txt"), 0o640)).To(Succeed())

		r, err := secureLoadIgnoreRules(tmpDir, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r.Ignore("file.txt", nil)).To(BeTrue())
		g.Expect(r.Ignore("templates/.dotfile", nil)).To(BeTrue())
		g.Expect(r.Ignore("other.txt", nil)).To(BeFalse())
	})

	t.Run("with chart path and "+ignore.HelmIgnore, func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		chartPath := "./sub/chart"
		g.Expect(os.MkdirAll(filepath.Join(tmpDir, chartPath), 0o700)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, chartPath, ignore.HelmIgnore), []byte("file.txt"), 0o640)).To(Succeed())

		r, err := secureLoadIgnoreRules(tmpDir, chartPath)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r.Ignore("file.txt", nil)).To(BeTrue())
	})

	t.Run("with relative "+ignore.HelmIgnore+" symlink", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		chartPath := "sub/chart"
		g.Expect(os.MkdirAll(filepath.Join(tmpDir, chartPath), 0o700)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "symlink"), []byte("file.txt"), 0o640)).To(Succeed())
		g.Expect(os.Symlink("../../symlink", filepath.Join(tmpDir, chartPath, ignore.HelmIgnore)))

		r, err := secureLoadIgnoreRules(tmpDir, chartPath)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r.Ignore("file.txt", nil)).To(BeTrue())
	})

	t.Run("with illegal "+ignore.HelmIgnore+" symlink", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		chartPath := "/sub/chart"
		g.Expect(os.MkdirAll(filepath.Join(tmpDir, chartPath), 0o700)).To(Succeed())
		g.Expect(os.WriteFile(filepath.Join(tmpDir, "symlink"), []byte("file.txt"), 0o640)).To(Succeed())
		g.Expect(os.Symlink("../../symlink", filepath.Join(tmpDir, chartPath, ignore.HelmIgnore)))

		r, err := secureLoadIgnoreRules(filepath.Join(tmpDir, chartPath), "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r.Ignore("templates/.dotfile", nil)).To(BeTrue())
		g.Expect(r.Ignore("file.txt", nil)).To(BeFalse())
	})

	t.Run("with "+ignore.HelmIgnore+" parsing error", func(t *testing.T) {
		g := NewWithT(t)

		tmpDir := t.TempDir()
		g.Expect(os.WriteFile(filepath.Join(tmpDir, ignore.HelmIgnore), []byte("**"), 0o640)).To(Succeed())

		_, err := secureLoadIgnoreRules(tmpDir, "")
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("syntax is not supported"))
	})
}

func Test_secureFileWalker_walk(t *testing.T) {
	g := NewWithT(t)

	const (
		root      = "/fake/root"
		chartPath = "/fake/root/dir"
	)

	fakeDirName := "fake-dir"
	fakeFileName := "fake-file"
	fakeDeviceFileName := "fake-device"
	fakeFS := fstest.MapFS{
		fakeDirName:        &fstest.MapFile{Mode: fs.ModeDir},
		fakeFileName:       &fstest.MapFile{Data: []byte("a couple bytes")},
		fakeDeviceFileName: &fstest.MapFile{Mode: fs.ModeDevice},
	}

	// Safe to further re-use this for other paths
	fakeDirInfo, err := fakeFS.Stat(fakeDirName)
	g.Expect(err).ToNot(HaveOccurred())
	fakeFileInfo, err := fakeFS.Stat(fakeFileName)
	g.Expect(err).ToNot(HaveOccurred())
	fakeDeviceInfo, err := fakeFS.Stat(fakeDeviceFileName)
	g.Expect(err).ToNot(HaveOccurred())

	t.Run("given name equals top dir", func(t *testing.T) {
		g := NewWithT(t)

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, ignore.Empty())
		g.Expect(w.walk(chartPath+"/", chartPath, nil, nil)).To(BeNil())
	})

	t.Run("given error is returned", func(t *testing.T) {
		g := NewWithT(t)

		err := errors.New("error argument")
		got := (&secureFileWalker{}).walk("name", "/name", nil, err)
		g.Expect(got).To(HaveOccurred())
		g.Expect(got).To(Equal(err))
	})

	t.Run("ignore rule matches dir", func(t *testing.T) {
		g := NewWithT(t)

		rules, err := ignore.Parse(strings.NewReader(fakeDirName + "/"))
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, rules)
		g.Expect(w.walk(filepath.Join(w.absChartPath, fakeDirName), filepath.Join(w.absChartPath, fakeDirName), fakeDirInfo, nil)).To(Equal(fs.SkipDir))
	})

	t.Run("absolute path match ignored", func(t *testing.T) {
		g := NewWithT(t)

		rules, err := ignore.Parse(strings.NewReader(fakeDirName + "/"))
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, rules)
		g.Expect(w.walk(filepath.Join(w.absChartPath, "symlink"), filepath.Join(w.absChartPath, fakeDirName), fakeDirInfo, nil)).To(BeNil())
	})

	t.Run("ignore rule not applicable to dir", func(t *testing.T) {
		g := NewWithT(t)

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, ignore.Empty())
		g.Expect(w.walk(filepath.Join(w.absChartPath, fakeDirName), filepath.Join(w.absChartPath, fakeDirName), fakeDirInfo, nil)).To(BeNil())
	})

	t.Run("absolute path outside root", func(t *testing.T) {
		g := NewWithT(t)

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, ignore.Empty())
		err := w.walk(filepath.Join(w.absChartPath, fakeDirName), filepath.Join("/fake/another/root/", fakeDirName), fakeDirInfo, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("cannot load 'fake-dir' directory: absolute path traverses outside root boundary"))
	})

	t.Run("dir ignore rules before secure path check", func(t *testing.T) {
		g := NewWithT(t)

		rules, err := ignore.Parse(strings.NewReader(fakeDirName + "/"))
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, rules)
		g.Expect(w.walk(filepath.Join(w.absChartPath, fakeDirName), filepath.Join("/fake/another/root/", fakeDirName), fakeDirInfo, nil)).To(Equal(fs.SkipDir))
	})

	t.Run("ignore rule matches file", func(t *testing.T) {
		g := NewWithT(t)

		rules, err := ignore.Parse(strings.NewReader(fakeFileName))
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, rules)
		g.Expect(w.walk(filepath.Join(w.absChartPath, fakeFileName), filepath.Join(w.absChartPath, fakeFileName), fakeFileInfo, nil)).To(BeNil())
	})

	t.Run("file path outside root", func(t *testing.T) {
		g := NewWithT(t)

		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, ignore.Empty())
		err := w.walk(filepath.Join(w.absChartPath, fakeFileName), filepath.Join("/fake/another/root/", fakeFileName), fakeFileInfo, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("cannot load 'fake-file' file: absolute path traverses outside root boundary"))
	})

	t.Run("irregular file", func(t *testing.T) {
		w := newSecureFileWalker(root, chartPath, helm.MaxChartFileSize, ignore.Empty())
		err := w.walk(fakeDeviceFileName, filepath.Join(w.absChartPath), fakeDeviceInfo, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("cannot load irregular file fake-device as it has file mode type bits set"))
	})

	t.Run("file exceeds max size", func(t *testing.T) {
		w := newSecureFileWalker(root, chartPath, 5, ignore.Empty())
		err := w.walk(fakeFileName, filepath.Join(w.absChartPath), fakeFileInfo, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(Equal(fmt.Sprintf("cannot load file fake-file as file size (%d) exceeds limit (%d)", fakeFileInfo.Size(), w.maxSize)))
	})

	t.Run("file is appended", func(t *testing.T) {
		g := NewWithT(t)
		tmpDir := t.TempDir()

		fileName := "append-file"
		fileData := []byte("append-file-data")
		absFilePath := filepath.Join(tmpDir, fileName)
		g.Expect(os.WriteFile(absFilePath, fileData, 0o640)).To(Succeed())
		fileInfo, err := os.Lstat(absFilePath)
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(tmpDir, tmpDir, helm.MaxChartFileSize, ignore.Empty())
		g.Expect(w.walk(fileName, absFilePath, fileInfo, nil)).To(Succeed())
		g.Expect(w.files).To(HaveLen(1))
		g.Expect(w.files[0].Name).To(Equal(fileName))
		g.Expect(w.files[0].Data).To(Equal(fileData))
	})

	t.Run("utf8bom is removed from file data", func(t *testing.T) {
		g := NewWithT(t)
		tmpDir := t.TempDir()

		fileName := "append-file"
		fileData := []byte("append-file-data")
		fileDataWithBom := append(utf8bom, fileData...)
		absFilePath := filepath.Join(tmpDir, fileName)
		g.Expect(os.WriteFile(absFilePath, fileDataWithBom, 0o640)).To(Succeed())
		fileInfo, err := os.Lstat(absFilePath)
		g.Expect(err).ToNot(HaveOccurred())

		w := newSecureFileWalker(tmpDir, tmpDir, helm.MaxChartFileSize, ignore.Empty())
		g.Expect(w.walk(fileName, absFilePath, fileInfo, nil)).To(Succeed())
		g.Expect(w.files).To(HaveLen(1))
		g.Expect(w.files[0].Name).To(Equal(fileName))
		g.Expect(w.files[0].Data).To(Equal(fileData))
	})

	t.Run("file does not exist", func(t *testing.T) {
		g := NewWithT(t)
		tmpDir := t.TempDir()

		w := newSecureFileWalker(tmpDir, tmpDir, helm.MaxChartFileSize, ignore.Empty())
		err := w.walk(filepath.Join(w.absChartPath, "invalid"), filepath.Join(w.absChartPath, "invalid"), fakeFileInfo, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue())
		g.Expect(err.Error()).To(ContainSubstring("error reading invalid: open /invalid: no such file or directory"))
	})
}

func Test_isSecureAbsolutePath(t *testing.T) {
	tests := []struct {
		name    string
		root    string
		absPath string
		safe    bool
		wantErr string
	}{
		{
			name:    "absolute path in root",
			root:    "/",
			absPath: "/bar/",
			safe:    true,
		},

		{
			name:    "abs path not relative to root",
			root:    "/working/dir",
			absPath: "/working/in/another/dir",
			safe:    false,
			wantErr: "absolute path traverses outside root boundary",
		},
		{
			name:    "abs path relative to root",
			root:    "/working/dir/",
			absPath: "/working/dir/path",
			safe:    true,
		},
		{
			name:    "illegal abs path",
			root:    "/working/dir",
			absPath: "/working/dir/../but/not/really",
			safe:    false,
			wantErr: "absolute path traverses outside root boundary",
		},
		{
			name:    "illegal root",
			root:    "working/dir/",
			absPath: "/working/dir",
			safe:    false,
			wantErr: "cannot calculate path relative to root for absolute path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := isSecureAbsolutePath(tt.root, tt.absPath)
			g.Expect(got).To(Equal(tt.safe))
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}
