package controllers

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
	"time"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

type ignoreMap map[string]bool

var remoteRepository = "https://github.com/fluxcd/source-controller"

func init() {
	// if this remote repo ever gets in your way, this is an escape; just set
	// this to the url you want to clone. Be the source you want to be.
	s := os.Getenv("REMOTE_REPOSITORY")
	if s != "" {
		remoteRepository = s
	}
}

func createStoragePath() (string, error) {
	return ioutil.TempDir("", "")
}

func cleanupStoragePath(dir string) func() {
	return func() { os.RemoveAll(dir) }
}

func TestStorageConstructor(t *testing.T) {
	dir, err := createStoragePath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanupStoragePath(dir))

	if _, err := NewStorage("/nonexistent", "hostname", time.Minute); err == nil {
		t.Fatal("nonexistent path was allowable in storage constructor")
	}

	f, err := ioutil.TempFile(dir, "")
	if err != nil {
		t.Fatalf("while creating temporary file: %v", err)
	}
	f.Close()

	if _, err := NewStorage(f.Name(), "hostname", time.Minute); err == nil {
		t.Fatal("file path was accepted as basedir")
	}

	os.Remove(f.Name())

	if _, err := NewStorage(dir, "hostname", time.Minute); err != nil {
		t.Fatalf("Valid path did not successfully return: %v", err)
	}
}

func artifactFromURLRepository(repo string) sourcev1.Artifact {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		panic(fmt.Errorf("could not create temporary file: %w", err))
	}
	f.Close()
	os.Remove(f.Name())

	return sourcev1.Artifact{Path: f.Name(), URL: repo}
}

// walks a tar.gz and looks for paths with the basename. It does not match
// symlinks properly at this time because that's painful.
func walkTar(tarFile string, match string) (bool, error) {
	f, err := os.Open(tarFile)
	if err != nil {
		return false, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return false, fmt.Errorf("could not unzip file: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return false, fmt.Errorf("Corrupt tarball reading header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			if filepath.Base(header.Name) == match {
				return true, nil
			}
		default:
			// skip
		}
	}

	return false, nil
}

func testPatterns(t *testing.T, artifact sourcev1.Artifact, table ignoreMap) {
	for name, expected := range table {
		res, err := walkTar(artifact.Path, name)
		if err != nil {
			t.Fatalf("while reading tarball: %v", err)
		}

		if res != expected {
			if expected {
				t.Fatalf("Could not find repository file matching %q in tarball for repo %q", name, remoteRepository)
			} else {
				t.Fatalf("Repository contained ignored file %q in tarball for repo %q", name, remoteRepository)
			}
		}
	}
}

func createArchive(t *testing.T, filenames []string, sourceIgnore string, spec sourcev1.GitRepositorySpec) sourcev1.Artifact {
	dir, err := createStoragePath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanupStoragePath(dir))

	storage, err := NewStorage(dir, "hostname", time.Minute)
	if err != nil {
		t.Fatalf("Error while bootstrapping storage: %v", err)
	}

	gitDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("could not create temporary directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(gitDir) })

	if err := exec.Command("git", "clone", remoteRepository, gitDir).Run(); err != nil {
		t.Fatalf("Could not clone remote repository: %v", err)
	}

	// inject files.. just empty files
	for _, name := range filenames {
		f, err := os.Create(filepath.Join(gitDir, name))
		if err != nil {
			t.Fatalf("Could not inject filename %q: %v", name, err)
		}
		f.Close()
	}

	// inject sourceignore if not empty
	if sourceIgnore != "" {
		si, err := os.Create(filepath.Join(gitDir, ".sourceignore"))
		if err != nil {
			t.Fatalf("Could not create .sourceignore: %v", err)
		}

		if _, err := io.WriteString(si, sourceIgnore); err != nil {
			t.Fatalf("Could not write to .sourceignore: %v", err)
		}

		si.Close()
	}
	artifact := artifactFromURLRepository(remoteRepository)

	if err := storage.Archive(artifact, gitDir, spec); err != nil {
		t.Fatalf("basic archive case failed: %v", err)
	}

	if !storage.ArtifactExist(artifact) {
		t.Fatalf("artifact was created but does not exist: %+v", artifact)
	}

	return artifact
}

func stringPtr(s string) *string {
	return &s
}

func TestArchiveBasic(t *testing.T) {
	table := ignoreMap{
		"README.md":  true,
		".gitignore": false,
	}

	testPatterns(t, createArchive(t, []string{"README.md", ".gitignore"}, "", sourcev1.GitRepositorySpec{}), table)
}

func TestArchiveIgnore(t *testing.T) {
	// this is a list of files that will be created in the repository for each
	// subtest. it is manipulated later on.
	filenames := []string{
		"foo.tar.gz",
		"bar.jpg",
		"bar.gif",
		"foo.jpeg",
		"video.flv",
		"video.wmv",
		"bar.png",
		"foo.zip",
	}

	// this is the table of ignored files and their values. true means that it's
	// present in the resulting tarball.
	table := ignoreMap{}
	for _, item := range filenames {
		table[item] = false
	}

	t.Run("automatically ignored files", func(t *testing.T) {
		testPatterns(t, createArchive(t, filenames, "", sourcev1.GitRepositorySpec{}), table)
	})

	table = ignoreMap{}
	for _, item := range filenames {
		table[item] = true
	}

	t.Run("only vcs ignored files", func(t *testing.T) {
		testPatterns(t, createArchive(t, filenames, "", sourcev1.GitRepositorySpec{Ignore: stringPtr("")}), table)
	})

	filenames = append(filenames, "test.txt")
	table["test.txt"] = false
	sourceIgnoreFile := "*.txt"

	t.Run("sourceignore injected via CRD", func(t *testing.T) {
		testPatterns(t, createArchive(t, filenames, "", sourcev1.GitRepositorySpec{Ignore: stringPtr(sourceIgnoreFile)}), table)
	})

	table = ignoreMap{}
	for _, item := range filenames {
		table[item] = false
	}

	t.Run("sourceignore injected via filename", func(t *testing.T) {
		testPatterns(t, createArchive(t, filenames, sourceIgnoreFile, sourcev1.GitRepositorySpec{}), table)
	})
}

func TestStorageRemoveAllButCurrent(t *testing.T) {
	t.Run("bad directory in archive", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })

		s, err := NewStorage(dir, "hostname", time.Minute)
		if err != nil {
			t.Fatalf("Valid path did not successfully return: %v", err)
		}

		if err := s.RemoveAllButCurrent(sourcev1.Artifact{Path: path.Join(dir, "really", "nonexistent")}); err == nil {
			t.Fatal("Did not error while pruning non-existent path")
		}
	})
}
