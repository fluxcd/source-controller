//go:build gofuzz
// +build gofuzz

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

package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	httptransport "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/testenv"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/controllers"
)

var (
	noOfCreatedFiles = 0
	interval         = time.Millisecond * 10
	indexInterval    = time.Millisecond * 10
	pullInterval     = time.Second * 3
	initter          sync.Once
	gitServer        *gittestserver.GitServer
	k8sClient        client.Client
	cfg              *rest.Config
	testEnv          *testenv.Environment

	storage *controllers.Storage

	examplePublicKey  []byte
	examplePrivateKey []byte
	exampleCA         []byte
)

//go:embed testdata/crd/*.yaml
//go:embed testdata/certs/*
var testFiles embed.FS

const (
	defaultBinVersion     = "1.23"
	lettersAndNumbers     = "abcdefghijklmnopqrstuvwxyz123456789"
	lettersNumbersAndDash = "abcdefghijklmnopqrstuvwxyz123456789-"
)

func envtestBinVersion() string {
	if binVersion := os.Getenv("ENVTEST_BIN_VERSION"); binVersion != "" {
		return binVersion
	}
	return defaultBinVersion
}

func ensureDependencies() error {
	if _, err := os.Stat("/.dockerenv"); os.IsNotExist(err) {
		return nil
	}

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		binVersion := envtestBinVersion()
		cmd := exec.Command("/usr/bin/bash", "-c", fmt.Sprintf(`go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest && \
		/root/go/bin/setup-envtest use -p path %s`, binVersion))

		cmd.Env = append(os.Environ(), "GOPATH=/root/go")
		assetsPath, err := cmd.Output()
		if err != nil {
			return err
		}
		os.Setenv("KUBEBUILDER_ASSETS", string(assetsPath))
	}

	// Output all embedded testdata files
	embedDirs := []string{"testdata/crd", "testdata/certs"}
	for _, dir := range embedDirs {
		err := os.MkdirAll(dir, 0o700)
		if err != nil {
			return fmt.Errorf("mkdir %s: %v", dir, err)
		}

		templates, err := fs.ReadDir(testFiles, dir)
		if err != nil {
			return fmt.Errorf("reading embedded dir: %v", err)
		}

		for _, template := range templates {
			fileName := fmt.Sprintf("%s/%s", dir, template.Name())
			fmt.Println(fileName)

			data, err := testFiles.ReadFile(fileName)
			if err != nil {
				return fmt.Errorf("reading embedded file %s: %v", fileName, err)
			}

			os.WriteFile(fileName, data, 0o600)
			if err != nil {
				return fmt.Errorf("writing %s: %v", fileName, err)
			}
		}
	}

	startEnvServer(func(m manager.Manager) {
		utilruntime.Must((&controllers.GitRepositoryReconciler{
			Client:  m.GetClient(),
			Storage: storage,
		}).SetupWithManager(m))
	})

	return nil
}

func startEnvServer(setupReconcilers func(manager.Manager)) *envtest.Environment {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("testdata", "crd")},
	}
	fmt.Println("Starting the test environment")
	cfg, err := testEnv.Start()
	if err != nil {
		panic(fmt.Sprintf("Failed to start the test environment manager: %v", err))
	}

	utilruntime.Must(loadExampleKeys())
	utilruntime.Must(sourcev1.AddToScheme(scheme.Scheme))

	tmpStoragePath, err := os.MkdirTemp("", "source-controller-storage-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpStoragePath)
	storage, err = controllers.NewStorage(tmpStoragePath, "localhost:5050", time.Minute*1, 2)
	if err != nil {
		panic(err)
	}
	// serve artifacts from the filesystem, as done in main.go
	fs := http.FileServer(http.Dir(tmpStoragePath))
	http.Handle("/", fs)
	go http.ListenAndServe(":5050", nil)

	cert, err := tls.X509KeyPair(examplePublicKey, examplePrivateKey)
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(exampleCA)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	var transport = httptransport.NewClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	})
	gitclient.InstallProtocol("https", transport)

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

	setupReconcilers(k8sManager)

	time.Sleep(2 * time.Second)
	go func() {
		fmt.Println("Starting k8sManager...")
		utilruntime.Must(k8sManager.Start(context.TODO()))
	}()

	return testEnv
}

// FuzzRandomGitFiles implements a fuzzer that
// targets the GitRepository reconciler.
func FuzzRandomGitFiles(data []byte) int {
	initter.Do(func() {
		utilruntime.Must(ensureDependencies())
	})

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
	initter.Do(func() {
		utilruntime.Must(ensureDependencies())
	})

	f := fuzz.NewConsumer(data)

	// Create this early because if it fails, then the fuzzer
	// does not need to proceed.
	repository := &sourcev1.GitRepository{}
	err := f.GenerateStruct(repository)
	if err != nil {
		return 0
	}

	metaName, err := f.GetStringFrom(lettersNumbersAndDash, 59)
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

// createGitRepository is a helper function to create GitRepository objects.
func createGitRepository(f *fuzz.ConsumeFuzzer, specUrl, commit, namespaceName string) (*sourcev1.GitRepository, error) {
	reference := &sourcev1.GitRepositoryRef{Branch: "some-branch"}
	reference.Commit = strings.Replace(reference.Commit, "<commit>", commit, 1)
	nnID, err := f.GetStringFrom(lettersAndNumbers, 10)
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

// createNamespace is a helper function to create kubernetes namespaces.
func createNamespace(f *fuzz.ConsumeFuzzer) (*corev1.Namespace, func(), error) {
	namespace := &corev1.Namespace{}
	nnID, err := f.GetStringFrom(lettersAndNumbers, 10)
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

// createGitServer is a helper function to create a git server.
func createGitServer(f *fuzz.ConsumeFuzzer) (*url.URL, func()) {
	repoID, err := f.GetStringFrom(lettersAndNumbers, 10)
	if err != nil {
		return &url.URL{}, func() {}
	}
	gitServer, err := gittestserver.NewTempGitServer()
	if err != nil {
		panic(err)
	}
	gitServer.AutoCreate()
	defer os.RemoveAll(gitServer.Root())

	utilruntime.Must(gitServer.StartHTTPS(examplePublicKey, examplePrivateKey, exampleCA, "example.com"))

	u, err := url.Parse(gitServer.HTTPAddress())
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, fmt.Sprintf("repository-%s.git", repoID))
	return u, func() { gitServer.StopHTTP() }
}

// pushFilesToGit is a helper function to push files to a git server.
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

// createRandomFiles is a helper function to create files in a billy.Filesystem.
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

		err = fs.MkdirAll(dirPath, 0o700)
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
