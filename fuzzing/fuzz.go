//go:build gofuzz
// +build gofuzz

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
package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/storage/memory"
	. "github.com/onsi/ginkgo"

	"github.com/fluxcd/pkg/helmtestserver"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/getter"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/fluxcd/pkg/gittestserver"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	noOfCreatedFiles = 0
	interval         = time.Millisecond * 10
	indexInterval    = time.Millisecond * 10
	pullInterval     = time.Second * 3
	initter          sync.Once
	cfg              *rest.Config
	k8sClient        client.Client
	testEnv          *envtest.Environment
	gitServer        *gittestserver.GitServer

	storage *Storage

	examplePublicKey  []byte
	examplePrivateKey []byte
	exampleCA         []byte
)

// createKUBEBUILDER_ASSETS runs "setup-envtest use"
func createKUBEBUILDER_ASSETS() string {
	out, err := exec.Command("setup-envtest", "use").Output()
	if err != nil {
		panic(err)
	}

	// split the output:
	splitString := strings.Split(string(out), " ")
	binPath := strings.TrimSuffix(splitString[len(splitString)-1], "\n")
	if err != nil {
		panic(err)
	}
	return binPath
}

func initBeforeFuzzing() {
	kubebuilder_assets := createKUBEBUILDER_ASSETS()
	os.Setenv("KUBEBUILDER_ASSETS", kubebuilder_assets)

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		panic(err)
	}
	if cfg == nil {
		panic("cfg is nil but should not be")
	}

	err = sourcev1.AddToScheme(scheme.Scheme)
	if err != nil {
		panic(err)
	}
	err = loadExampleKeys()
	if err != nil {
		panic(err)
	}

	tmpStoragePath, err := os.MkdirTemp("", "source-controller-storage-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpStoragePath)
	storage, err = NewStorage(tmpStoragePath, "localhost:5050", time.Second*30)
	if err != nil {
		panic(err)
	}
	// serve artifacts from the filesystem, as done in main.go
	fs := http.FileServer(http.Dir(tmpStoragePath))
	http.Handle("/", fs)
	go http.ListenAndServe(":5050", nil)

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		panic(err)
	}
	if k8sClient == nil {
		panic("cfg is nil but should not be")
	}

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		panic(err)
	}

	err = (&GitRepositoryReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: storage,
	}).SetupWithManager(k8sManager)
	if err != nil {
		panic(err)
	}
	err = (&HelmRepositoryReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: storage,
		Getters: getter.Providers{getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		}},
	}).SetupWithManager(k8sManager)
	if err != nil {
		panic(err)
	}
	err = (&HelmChartReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: storage,
		Getters: getter.Providers{getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		}},
	}).SetupWithManager(k8sManager)
	if err != nil {
		panic(err)
	}
	time.Sleep(2 * time.Second)
	go func() {
		fmt.Println("Starting k8sManager...")
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		if err != nil {
			panic(err)
		}
	}()
}

// generateValidUrl is a utility function that
// create a string a prepends a prefix to make
// that string look like a URL.
func generateValidUrl(f *fuzz.ConsumeFuzzer) (string, error) {
	randNumber, err := f.GetInt()
	var newStr string
	if err != nil {
		return "", errors.New("Err")
	}
	randString, err := f.GetString()
	if err != nil {
		return "", err
	}
	if randNumber%1 == 0 {
		newStr = "http://" + randString
		_, err = url.Parse(newStr)
		if err != nil {
			return "", errors.New("Err")
		}
		return newStr, nil
	} else if randNumber%2 == 0 {
		newStr = "https://" + randString
		_, err = url.Parse(newStr)
		if err != nil {
			return "", errors.New("Err")
		}
		return newStr, nil
	} else if randNumber%3 == 0 {
		newStr = "ssh://" + randString
		_, err = url.Parse(newStr)
		if err != nil {
			return "", errors.New("Err")
		}
		return newStr, nil
	}
	return "", errors.New("Err")
}

// Allows the fuzzer to create a GitRepository
// Just a utility. The GitRepository is not created
// by the client.
func createGitRepository(f *fuzz.ConsumeFuzzer, specUrl, commit, namespaceName string) (*sourcev1.GitRepository, error) {
	reference := &sourcev1.GitRepositoryRef{Branch: "some-branch"}
	reference.Commit = strings.Replace(reference.Commit, "<commit>", commit, 1)
	nnID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return &sourcev1.GitRepository{}, err
	}
	key := types.NamespacedName{
		Name:      fmt.Sprintf("git-ref-test-%s", nnID),
		Namespace: namespaceName,
	}

	return &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
		},
		Spec: sourcev1.GitRepositorySpec{
			URL:       specUrl,
			Interval:  metav1.Duration{Duration: indexInterval},
			Reference: reference,
		},
	}, nil
}

// Allows the fuzzer to create a namespace.
// The namespace is created by the client in this func,
// and a cleanup func is returned.
func createNamespace(f *fuzz.ConsumeFuzzer) (*corev1.Namespace, func(), error) {
	namespace := &corev1.Namespace{}
	nnID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return namespace, func() {}, err
	}
	namespace.ObjectMeta = metav1.ObjectMeta{Name: "git-repository-test" + nnID}
	err = k8sClient.Create(context.Background(), namespace)
	if err != nil {
		return namespace, func() {}, err
	}
	return namespace, func() {
		k8sClient.Delete(context.Background(), namespace)
	}, nil
}

// createGitServer is a utility function that creates a git test
// server
func createGitServer(f *fuzz.ConsumeFuzzer) (*url.URL, func()) {
	repoID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return &url.URL{}, func() {}
	}
	gitServer, err := gittestserver.NewTempGitServer()
	if err != nil {
		panic(err)
	}
	gitServer.AutoCreate()
	defer os.RemoveAll(gitServer.Root())

	err = gitServer.StartHTTP()
	if err != nil {
		panic(err)
	}
	u, err := url.Parse(gitServer.HTTPAddress())
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, fmt.Sprintf("repository-%s.git", repoID))
	return u, func() { gitServer.StopHTTP() }
}

// pushFilesToGit is a utility function to push files
// to a gitserver when fuzzing.
func pushFilesToGit(gitrepo *git.Repository, wt *git.Worktree, gitServerURL string) (plumbing.Hash, error) {
	commit, err := wt.Commit("Sample", &git.CommitOptions{Author: &object.Signature{
		Name:  "John Doe",
		Email: "john@example.com",
		When:  time.Now(),
	}})
	if err != nil {
		return plumbing.ZeroHash, err
	}
	hRef := plumbing.NewHashReference(plumbing.ReferenceName("refs/heads/some-branch"), commit)
	err = gitrepo.Storer.SetReference(hRef)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	remote, err := gitrepo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{gitServerURL},
	})
	if err != nil {
		return plumbing.ZeroHash, err
	}
	err = remote.Push(&git.PushOptions{
		RefSpecs: []config.RefSpec{"refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"},
	})
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return commit, nil

}

// FuzzRandomGitFiles implements a fuzzer that
// targets the GitRepository reconciler
func FuzzRandomGitFiles(data []byte) int {
	initter.Do(initBeforeFuzzing)
	f := fuzz.NewConsumer(data)
	namespace, deleteNamespace, err := createNamespace(f)
	if err != nil {
		return 0
	}
	defer deleteNamespace()

	gitServerURL, stopGitServer := createGitServer(f)
	defer stopGitServer()

	fs := memfs.New()
	gitrepo, err := git.Init(memory.NewStorage(), fs)
	if err != nil {
		panic(err)
	}
	wt, err := gitrepo.Worktree()
	if err != nil {
		panic(err)
	}

	// Create random files for the git source
	err = createRandomFiles(f, fs, wt)
	if err != nil {
		return 0
	}

	commit, err := pushFilesToGit(gitrepo, wt, gitServerURL.String())
	if err != nil {
		return 0
	}
	created, err := createGitRepository(f, gitServerURL.String(), commit.String(), namespace.Name)
	if err != nil {
		return 0
	}
	err = k8sClient.Create(context.Background(), created)
	if err != nil {
		return 0
	}
	defer k8sClient.Delete(context.Background(), created)

	// Let the reconciler do its thing:
	time.Sleep(60 * time.Millisecond)

	return 1
}

// FuzzGitResourceObject implements a fuzzer that targets
// the GitRepository reconciler.
func FuzzGitResourceObject(data []byte) int {
	initter.Do(initBeforeFuzzing)
	f := fuzz.NewConsumer(data)

	// Create this early because if this fails, then the fuzzer
	// does not need to proceed.
	repository := &sourcev1.GitRepository{}
	err := f.GenerateStruct(repository)
	if err != nil {
		return 0
	}

	metaName, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789-", 59)
	if err != nil {
		return 0
	}

	gitServerURL, stopGitServer := createGitServer(f)
	defer stopGitServer()

	fs := memfs.New()
	gitrepo, err := git.Init(memory.NewStorage(), fs)
	if err != nil {
		return 0
	}
	wt, err := gitrepo.Worktree()
	if err != nil {
		return 0
	}

	// Add a file
	ff, _ := fs.Create("fixture")
	_ = ff.Close()
	_, err = wt.Add(fs.Join("fixture"))
	if err != nil {
		return 0
	}

	commit, err := pushFilesToGit(gitrepo, wt, gitServerURL.String())
	if err != nil {
		return 0
	}

	namespace, deleteNamespace, err := createNamespace(f)
	if err != nil {
		return 0
	}
	defer deleteNamespace()

	repository.Spec.URL = gitServerURL.String()
	repository.Spec.Verification.Mode = "head"
	repository.Spec.SecretRef = nil

	reference := &sourcev1.GitRepositoryRef{Branch: "some-branch"}
	reference.Commit = strings.Replace(reference.Commit, "<commit>", commit.String(), 1)
	repository.Spec.Reference = reference

	repository.ObjectMeta = metav1.ObjectMeta{
		Name:      metaName,
		Namespace: namespace.Name,
	}
	err = k8sClient.Create(context.Background(), repository)
	if err != nil {
		return 0
	}
	defer k8sClient.Delete(context.Background(), repository)

	// Let the reconciler do its thing.
	time.Sleep(50 * time.Millisecond)
	return 1
}

// createValidChartBytes creates valid file contents for Chart.yaml
// Is a utility function.
func createValidChartBytes(f *fuzz.ConsumeFuzzer) ([]byte, error) {
	chartBytes, err := f.GetBytes()
	if err != nil {
		return []byte{}, err
	}
	// Validate chart bytes
	metadata := &chart.Metadata{}
	if err := yaml.Unmarshal(chartBytes, metadata); err != nil {
		return []byte{}, err
	}
	return chartBytes, nil
}

// createChartPackagePath creates a directory for a helm chart.
// if createFiles is true, random files are created as well.
// Is a utility function.
func createChartPackagePath(f *fuzz.ConsumeFuzzer, createFiles bool) (string, func(), error) {
	var validChartBytes []byte
	var err error
	if createFiles {
		// Create bytes for the chart file
		validChartBytes, err = createValidChartBytes(f)
		if err != nil {
			return "", func() {}, err
		}
	}
	chartPackagePathID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return "", func() {}, err
	}

	chartPackagePath, err := os.MkdirTemp("", fmt.Sprintf("chartpackage-%s", chartPackagePathID))
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		os.RemoveAll(chartPackagePath)
	}

	if createFiles {
		// Create the files in the helm chart
		err = f.CreateFiles(chartPackagePath)
		if err != nil {
			return chartPackagePath, cleanup, err
		}
		// Create the Chart.yaml file manually. This is required
		chartFile, err := os.Create(filepath.Join(chartPackagePath, "Chart.yaml"))
		if err != nil {
			return chartPackagePath, cleanup, err
		}
		_, err = chartFile.Write(validChartBytes)
		if err != nil {
			chartFile.Close()
			return chartPackagePath, cleanup, err
		}
		chartFile.Close()
	}
	return chartPackagePath, cleanup, nil
}

// FuzzHelmchartController implements a fuzzer that targets
// the HelmChart reconciler
func FuzzHelmchartController(data []byte) int {
	initter.Do(initBeforeFuzzing)

	f := fuzz.NewConsumer(data)

	// Create dir with files for the chart.
	createFiles := true
	chartPackagePath, deleteDir, err := createChartPackagePath(f, createFiles)
	if err != nil {
		return 0
	}
	defer deleteDir()

	// Create a namespace
	namespace, deleteNamespace, err := createNamespace(f)
	if err != nil {
		return 0
	}
	defer deleteNamespace()

	// Create the helm test server
	var helmServer *helmtestserver.HelmServer
	helmServer, err = helmtestserver.NewTempHelmServer()
	if err != nil {
		return 0
	}
	helmServer.Start()
	defer func() {
		os.RemoveAll(helmServer.Root())
		helmServer.Stop()
	}()

	// Package the helm chart, we created.
	err = helmServer.PackageChart(chartPackagePath)
	if err != nil {
		return 0
	}

	// Create a HelmRepository
	repoKeyName, _, deleteRepository, err := createHelmRepository(f, helmServer.URL(), namespace.Name)
	if err != nil {
		return 0
	}
	defer deleteRepository()

	// Create a HelmChart
	_, deleteChart, err := createHelmChart(f, namespace.Name, repoKeyName)
	if err != nil {
		return 0
	}
	defer deleteChart()

	// Let the reconciler do its thing
	time.Sleep(60 * time.Millisecond)
	return 1
}

// FuzzStorageArchive implements a fuzzer that targets
// storage.Archive()
func FuzzStorageArchive(data []byte) int {
	dir, err := os.MkdirTemp("", "storage-dir-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)
	dir2, err := os.MkdirTemp("", "dir-to-create-files-in-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir2)
	storage, err := NewStorage(dir, "hostname", time.Minute)
	if err != nil {
		return 0
	}
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles(dir2)
	if err != nil {
		return 0
	}
	artifact := sourcev1.Artifact{
		Path: filepath.Join("dir1", "dir2", "dir3.tar.gz"),
	}
	if err = storage.MkdirAll(artifact); err != nil {
		panic(err)
	}
	if err := storage.Archive(&artifact, dir2, nil); err != nil {
		return 0
	}
	return 1
}

// FuzzStorageCopy implements a fuzzer that targets
// storage.Copy()
func FuzzStorageCopy(data []byte) int {
	dir, err := os.MkdirTemp("", "fuzz-archive-test-files-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)
	storage, err := NewStorage(dir, "hostname", time.Minute)
	if err != nil {
		panic(err)
	}
	f := fuzz.NewConsumer(data)
	artifact := sourcev1.Artifact{Path: dir}
	err = storage.MkdirAll(artifact)
	if err != nil {
		panic(err)
	}
	noOfCopies, err := f.GetInt()
	if err != nil {
		return 0
	}
	// Copy over maximum 30 files
	for i := 0; i < noOfCopies%30; i++ {
		rBytes, err := f.GetBytes()
		if err != nil {
			return 0
		}
		_ = storage.Copy(&artifact, bytes.NewReader(rBytes))
	}
	return 1
}

// createHelmRepository creates a HelmRepository.
// Is a utility function.
func createHelmRepository(f *fuzz.ConsumeFuzzer, helmserverURL, namespace string) (string, *sourcev1.HelmRepository, func(), error) {
	namespacedNameID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return "", &sourcev1.HelmRepository{}, func() {}, err
	}
	repositoryKey := types.NamespacedName{
		Name:      "helmrepository-sample-" + namespacedNameID,
		Namespace: namespace,
	}
	repository := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      repositoryKey.Name,
			Namespace: repositoryKey.Namespace,
		},
		Spec: sourcev1.HelmRepositorySpec{
			URL:      helmserverURL,
			Interval: metav1.Duration{Duration: indexInterval},
		},
	}
	err = k8sClient.Create(context.Background(), repository)
	if err != nil {
		return "", &sourcev1.HelmRepository{}, func() {}, err
	}
	cleanup := func() {
		_ = k8sClient.Delete(context.Background(), repository)
	}
	return repositoryKey.Name, repository, cleanup, nil
}

// createHelmChart create a HelmChart. The HelmChart is created
// in this function, and a cleanup function is returned.
// Is a utility function.
func createHelmChart(f *fuzz.ConsumeFuzzer, namespaceName, repositoryKeyName string) (*sourcev1.HelmChart, func(), error) {
	namespacedNameID, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789", 10)
	if err != nil {
		return &sourcev1.HelmChart{}, func() {}, err
	}
	key := types.NamespacedName{
		Name:      "helmchart-sample-" + namespacedNameID,
		Namespace: namespaceName,
	}
	created := &sourcev1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
		},
		Spec: sourcev1.HelmChartSpec{
			Chart:   "helmchart",
			Version: "",
			SourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.HelmRepositoryKind,
				Name: repositoryKeyName,
			},
			Interval: metav1.Duration{Duration: pullInterval},
		},
	}
	err = k8sClient.Create(context.Background(), created)
	if err != nil {
		return created, func() {}, err
	}
	cleanup := func() {
		_ = k8sClient.Delete(context.Background(), created)
	}
	return created, cleanup, nil
}

// loads the testdata certs.
// Is a utility function.
func loadExampleKeys() (err error) {
	examplePublicKey, err = os.ReadFile("testdata/certs/server.pem")
	if err != nil {
		return err
	}
	examplePrivateKey, err = os.ReadFile("testdata/certs/server-key.pem")
	if err != nil {
		return err
	}
	exampleCA, err = os.ReadFile("testdata/certs/ca.pem")
	return err
}

// createRandomFiles is a helper function to allow the fuzzer
// to create files in a billy.Filesystem.
// Is a utility function.
func createRandomFiles(f *fuzz.ConsumeFuzzer, fs billy.Filesystem, wt *git.Worktree) error {
	numberOfFiles, err := f.GetInt()
	if err != nil {
		return err
	}
	maxNumberOfFiles := 4000 // This number is completely arbitrary
	if numberOfFiles%maxNumberOfFiles == 0 {
		return errors.New("We don't want to create 0 files...")
	}

	for i := 0; i < numberOfFiles%maxNumberOfFiles; i++ {
		dirPath, err := f.GetString()
		if err != nil {
			return err
		}

		// Check for ".." cases
		if strings.Contains(dirPath, "..") {
			return errors.New("Dir contains '..'")
		}

		err = fs.MkdirAll(dirPath, 0777)
		if err != nil {
			return errors.New("Could not create the subDir")
		}
		fileName, err := f.GetString()
		if err != nil {
			return errors.New("Could not get fileName")
		}
		fullFilePath := fs.Join(dirPath, fileName)

		fileContents, err := f.GetBytes()
		if err != nil {
			return errors.New("Could not create the subDir")
		}

		createdFile, err := fs.Create(fullFilePath)
		if err != nil {
			return errors.New("Could not create the subDir")
		}
		_, err = createdFile.Write(fileContents)
		if err != nil {
			createdFile.Close()
			return errors.New("Could not create the subDir")
		}
		createdFile.Close()
		_, err = wt.Add(fullFilePath)
		if err != nil {
			panic(err)
		}
		noOfCreatedFiles++
	}
	return nil
}
