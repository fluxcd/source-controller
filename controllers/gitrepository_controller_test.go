/*
Copyright 2020 The Flux authors

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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/ssh"
	"github.com/go-git/go-billy/v5/memfs"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	sshtestdata "golang.org/x/crypto/ssh/testdata"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/controller"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/testenv"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/fake"
)

var (
	timeout                = 10 * time.Second
	mockInterval           = 1 * time.Second
	testGitImplementations = []string{sourcev1.GoGitImplementation, sourcev1.LibGit2Implementation}
)

var (
	testTLSPublicKey  []byte
	testTLSPrivateKey []byte
	testTLSCA         []byte
)

var (
	newTestEnv    *testenv.TestEnvironment
	eventsHelper  controller.Events
	metricsHelper controller.Metrics
	ctx           = ctrl.SetupSignalHandler()
)

func TestGitRepositoryReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "gitrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.GitRepositorySpec{
			URL: "https://github.com/stefanprodan/podinfo.git",
		},
	}
	g.Expect(newTestEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for GitRepository to be Ready
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}

		if !conditions.Has(obj, sourcev1.ArtifactAvailableCondition) ||
			!conditions.Has(obj, sourcev1.SourceAvailableCondition) ||
			!conditions.Has(obj, meta.ReadyCondition) ||
			obj.Status.Artifact == nil {
			return false
		}

		readyCondition := conditions.Get(obj, meta.ReadyCondition)

		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration
	}, timeout).Should(BeTrue())

	g.Expect(newTestEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for GitRepository to be deleted
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func TestGitRepositoryReconciler_reconcileSource_authStrategy(t *testing.T) {
	type options struct {
		username   string
		password   string
		publicKey  []byte
		privateKey []byte
		ca         []byte
	}

	tests := []struct {
		name                  string
		skipForImplementation string
		protocol              string
		server                options
		secret                *corev1.Secret
		beforeFunc            func(obj *sourcev1.GitRepository)
		want                  ctrl.Result
		wantErr               bool
		assertConditions      []metav1.Condition
	}{
		{
			name:     "HTTP",
			protocol: "http",
			want:     ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "SuccessfulCheckout", "Checked out revision master/<commit> from <url>"),
			},
		},
		{
			name:     "HTTP with BasicAuth",
			protocol: "http",
			server: options{
				username: "git",
				password: "1234",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "basic-auth",
				},
				Data: map[string][]byte{
					"username": []byte("git"),
					"password": []byte("1234"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "basic-auth"}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "SuccessfulCheckout", "Checked out revision master/<commit> from <url>"),
			},
		},
		{
			name:     "HTTPS with CAFile",
			protocol: "https",
			server: options{
				publicKey:  testTLSPublicKey,
				privateKey: testTLSPrivateKey,
				ca:         testTLSCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": testTLSCA,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "SuccessfulCheckout", "Checked out revision master/<commit> from <url>"),
			},
		},
		{
			name:                  "HTTPS with invalid CAFile (go-git)",
			skipForImplementation: sourcev1.LibGit2Implementation,
			protocol:              "https",
			server: options{
				publicKey:  testTLSPublicKey,
				privateKey: testTLSPrivateKey,
				ca:         testTLSCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-ca",
				},
				Data: map[string][]byte{
					"caFile": []byte("invalid"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-ca"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "GitOperationFailed", "Failed to checkout and determine HEAD revision: unable to clone '<url>', error: Get \"<url>/info/refs?service=git-upload-pack\": x509: certificate signed by unknown authority"),
			},
		},
		{
			name:                  "HTTPS with invalid CAFile (libgit2)",
			skipForImplementation: sourcev1.GoGitImplementation,
			protocol:              "https",
			server: options{
				publicKey:  testTLSPublicKey,
				privateKey: testTLSPrivateKey,
				ca:         testTLSCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-ca",
				},
				Data: map[string][]byte{
					"caFile": []byte("invalid"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-ca"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "GitOperationFailed", "Failed to checkout and determine HEAD revision: unable to clone '<url>', error: Certificate"),
			},
		},
		{
			name:     "SSH with private key",
			protocol: "ssh",
			server: options{
				username: "git",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "private-key",
				},
				Data: map[string][]byte{
					"username": []byte("git"),
					"identity": sshtestdata.PEMBytes["rsa"],
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "private-key"}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "SuccessfulCheckout", "Checked out revision master/<commit> from <url>"),
			},
		},
		{
			name:     "SSH with password protected private key",
			protocol: "ssh",
			server: options{
				username: "git",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "private-key",
				},
				Data: map[string][]byte{
					"username": []byte("git"),
					"identity": sshtestdata.PEMEncryptedKeys[2].PEMBytes,
					"password": []byte("password"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "private-key"}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "SuccessfulCheckout", "Checked out revision master/<commit> from <url>"),
			},
		},
		{
			name:     "Missing secret",
			protocol: "http",
			server: options{
				username: "git",
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "AuthenticationFailed", "Failed to get auth secret /non-existing: secrets \"non-existing\" not found"),
			},
		},
	}

	for _, tt := range tests {
		obj := &sourcev1.GitRepository{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "auth-strategy-",
			},
			Spec: sourcev1.GitRepositorySpec{
				Interval: metav1.Duration{Duration: mockInterval},
				Timeout:  &metav1.Duration{Duration: mockInterval},
			},
		}

		s := runtime.NewScheme()
		utilruntime.Must(corev1.AddToScheme(s))

		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			server, err := gittestserver.NewTempGitServer()
			g.Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(server.Root())
			server.AutoCreate()

			repoPath := "/test.git"
			localRepo, err := initGitRepo(server, "testdata/git/repository", git.DefaultBranch, repoPath)
			g.Expect(err).NotTo(HaveOccurred())

			if len(tt.server.username+tt.server.password) > 0 {
				server.Auth(tt.server.username, tt.server.password)
			}

			secret := tt.secret.DeepCopy()
			switch tt.protocol {
			case "http":
				g.Expect(server.StartHTTP()).To(Succeed())
				defer server.StopHTTP()
				obj.Spec.URL = server.HTTPAddress() + repoPath
			case "https":
				g.Expect(server.StartHTTPS(tt.server.publicKey, tt.server.privateKey, tt.server.ca, "example.com")).To(Succeed())
				obj.Spec.URL = server.HTTPAddress() + repoPath
			case "ssh":
				server.KeyDir(filepath.Join(server.Root(), "keys"))

				g.Expect(server.ListenSSH()).To(Succeed())
				obj.Spec.URL = server.SSHAddress() + repoPath

				go func() {
					server.StartSSH()
				}()
				defer server.StopSSH()

				if secret != nil && len(secret.Data["known_hosts"]) == 0 {
					u, err := url.Parse(obj.Spec.URL)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(u.Host).ToNot(BeEmpty())
					knownHosts, err := ssh.ScanHostKey(u.Host, timeout)
					g.Expect(err).NotTo(HaveOccurred())
					secret.Data["known_hosts"] = knownHosts
				}
			default:
				t.Fatalf("unsupported protocol %q", tt.protocol)
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			builder := fakeclient.NewClientBuilder().WithScheme(s)
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			r := &GitRepositoryReconciler{
				Client:  builder.Build(),
				Storage: storage,
			}

			for _, i := range testGitImplementations {
				t.Run(i, func(t *testing.T) {
					g := NewWithT(t)

					if tt.skipForImplementation == i {
						t.Skipf("Skipped for Git implementation %q", i)
					}

					tmpDir, err := ioutil.TempDir("", "auth-strategy-")
					g.Expect(err).To(BeNil())
					defer os.RemoveAll(tmpDir)

					obj := obj.DeepCopy()
					obj.Spec.GitImplementation = i

					head, _ := localRepo.Head()
					assertConditions := tt.assertConditions
					for k := range assertConditions {
						assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<commit>", head.Hash().String())
						assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", obj.Spec.URL)
					}

					var artifact sourcev1.Artifact
					got, err := r.reconcileSource(logr.NewContext(ctx, log.NullLogger{}), obj, &artifact, tmpDir)
					g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
					g.Expect(err != nil).To(Equal(tt.wantErr))
					g.Expect(got).To(Equal(tt.want))
					g.Expect(artifact).ToNot(BeNil())
				})
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileSource_checkoutStrategy(t *testing.T) {
	g := NewWithT(t)

	branches := []string{"staging"}
	tags := []string{"non-semver-tag", "v0.1.0", "0.2.0", "v0.2.1", "v1.0.0-alpha", "v1.1.0", "v2.0.0"}

	tests := []struct {
		name         string
		reference    *sourcev1.GitRepositoryRef
		want         ctrl.Result
		wantErr      bool
		wantRevision string
	}{
		{
			name:         "Nil reference (default branch)",
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "master/<commit>",
		},
		{
			name: "Branch",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "staging/<commit>",
		},
		{
			name: "Tag",
			reference: &sourcev1.GitRepositoryRef{
				Tag: "v0.1.0",
			},
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "v0.1.0/<commit>",
		},
		{
			name: "Branch commit",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
				Commit: "<commit>",
			},
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "staging/<commit>",
		},
		{
			name: "SemVer",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "*",
			},
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "v2.0.0/<commit>",
		},
		{
			name: "SemVer range",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "<v0.2.1",
			},
			want:         ctrl.Result{RequeueAfter: mockInterval},
			wantRevision: "0.2.0/<commit>",
		},
		{
			name: "SemVer prerelease",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: ">=1.0.0-0 <1.1.0-0",
			},
			wantRevision: "v1.0.0-alpha/<commit>",
			want:         ctrl.Result{RequeueAfter: mockInterval},
		},
	}

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).To(BeNil())
	server.AutoCreate()
	g.Expect(server.StartHTTP()).To(Succeed())
	defer server.StopHTTP()

	repoPath := "/test.git"
	localRepo, err := initGitRepo(server, "testdata/git/repository", git.DefaultBranch, repoPath)
	g.Expect(err).NotTo(HaveOccurred())

	headRef, err := localRepo.Head()
	g.Expect(err).NotTo(HaveOccurred())

	for _, branch := range branches {
		g.Expect(remoteBranchForHead(localRepo, headRef, branch)).To(Succeed())
	}
	for _, tag := range tags {
		g.Expect(remoteTagForHead(localRepo, headRef, tag)).To(Succeed())
	}

	r := &GitRepositoryReconciler{
		Client:  fakeclient.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
		Storage: storage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval:  metav1.Duration{Duration: mockInterval},
					Timeout:   &metav1.Duration{Duration: mockInterval},
					URL:       server.HTTPAddress() + repoPath,
					Reference: tt.reference,
				},
			}

			if obj.Spec.Reference != nil && obj.Spec.Reference.Commit == "<commit>" {
				obj.Spec.Reference.Commit = headRef.Hash().String()
			}

			for _, i := range testGitImplementations {
				t.Run(i, func(t *testing.T) {
					g := NewWithT(t)

					tmpDir, err := ioutil.TempDir("", "checkout-strategy-")
					g.Expect(err).NotTo(HaveOccurred())

					obj := obj.DeepCopy()
					obj.Spec.GitImplementation = i

					var artifact sourcev1.Artifact
					got, err := r.reconcileSource(ctx, obj, &artifact, tmpDir)
					if err != nil {
						println(err.Error())
					}
					g.Expect(err != nil).To(Equal(tt.wantErr))
					g.Expect(got).To(Equal(tt.want))
					if tt.wantRevision != "" {
						revision := strings.ReplaceAll(tt.wantRevision, "<commit>", headRef.Hash().String())
						g.Expect(artifact.Revision).To(Equal(revision))
					}
				})
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		dir              string
		beforeFunc       func(obj *sourcev1.GitRepository)
		afterFunc        func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archive artifact",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).NotTo(BeEmpty())
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactAvailableCondition, "ArchivedArtifact", "Artifact revision main/revision"),
			},
		},
		{
			name: "Invalid directory",
			dir:  "/a/random/invalid/path",
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact) {
				t.Expect(obj.GetArtifact()).To(BeNil())
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				{
					Type:    sourcev1.ArtifactAvailableCondition,
					Status:  metav1.ConditionFalse,
					Reason:  sourcev1.StorageOperationFailedReason,
					Message: "Failed to stat source path: stat /a/random/invalid/path: no such file or directory",
				},
			},
		},
		{
			name: "Spec ignore overwrite",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				obj.Spec.Ignore = pointer.StringPtr("!**.txt\n")
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).NotTo(BeEmpty())
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactAvailableCondition, "ArchivedArtifact", "Archived artifact revision main/revision"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &GitRepositoryReconciler{
				Storage: storage,
			}

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
					Generation:   1,
				},
				Status: sourcev1.GitRepositoryStatus{},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := storage.NewArtifactFor(obj.Kind, obj, "main/revision", "checksum.tar.gz")

			got, err := r.reconcileArtifact(ctx, obj, artifact, nil, tt.dir)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj, artifact)
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileInclude(t *testing.T) {
	g := NewWithT(t)

	storage, err := newTestStorage()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(storage.BasePath)

	dependencyInterval := 5 * time.Second

	type dependency struct {
		name         string
		withArtifact bool
		conditions   []metav1.Condition
	}

	type include struct {
		name     string
		fromPath string
		toPath   string
		shouldExist bool
	}

	tests := []struct {
		name             string
		dependencies     []dependency
		includes         []include
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Includes artifacts",
			dependencies: []dependency{
				{
					name:         "a",
					withArtifact: true,
					conditions: []metav1.Condition{
						*conditions.TrueCondition(meta.ReadyCondition, "Foo", "foo ready"),
					},
				},
				{
					name:         "b",
					withArtifact: true,
					conditions: []metav1.Condition{
						*conditions.TrueCondition(meta.ReadyCondition, "Bar", "bar ready"),
					},
				},
			},
			includes: []include{
				{name: "a", toPath: "a/"},
				{name: "b", toPath: "b/"},
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceAvailableCondition, "Foo", "2 of 2 Ready"),
			},
		},
		{
			name: "Non existing artifact",
			includes: []include{
				{name: "a", toPath: "a/"},
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			wantErr: false,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "IncludeNotFound", "Could not find resource for include \"a\": gitrepositories.source.toolkit.fluxcd.io \"a\" not found"),
			},
		},
		{
			name: "Missing artifact",
			dependencies: []dependency{
				{
					name:         "a",
					withArtifact: false,
					conditions: []metav1.Condition{
						*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "Foo", "foo unavailable"),
					},
				},
			},
			includes: []include{
				{name: "a", toPath: "a/"},
			},
			want: ctrl.Result{RequeueAfter: dependencyInterval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "IncludeUnavailable", "No artifact available for include \"a\""),
			},
		},
		{
			name: "Invalid FromPath",
			dependencies: []dependency{
				{
					name:         "a",
					withArtifact: true,
				},
			},
			includes: []include{
				{name: "a", fromPath: "../../../path", shouldExist: false},
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "IncludeCopyFailure", "Failed to copy \"a\" include from ../../../path to a"),
			},
		},
		{
			name: "Stalled include",
			dependencies: []dependency{
				{
					name:         "a",
					withArtifact: true,
					conditions: []metav1.Condition{
						*conditions.TrueCondition(meta.ReadyCondition, "Foo", "foo ready"),
					},
				},
				{
					name:         "b",
					withArtifact: true,
					conditions: []metav1.Condition{
						*conditions.TrueCondition(meta.StalledCondition, "Bar", "bar stalled"),
					},
				},
			},
			includes: []include{
				{name: "a", toPath: "a/"},
				{name: "b", toPath: "b/"},
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceAvailableCondition, "Bar @ GitRepository/a", "bar stalled"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var depObjs []client.Object
			for _, d := range tt.dependencies {
				obj := &sourcev1.GitRepository{
					ObjectMeta: metav1.ObjectMeta{
						Name: d.name,
					},
					Status: sourcev1.GitRepositoryStatus{
						Conditions: d.conditions,
					},
				}
				if d.withArtifact {
					obj.Status.Artifact = &sourcev1.Artifact{
						Path:           d.name + ".tar.gz",
						Revision:       d.name,
						LastUpdateTime: metav1.Now(),
					}
					g.Expect(storage.Archive(obj.GetArtifact(), "testdata/git/repository", nil)).To(Succeed())
				}
				depObjs = append(depObjs, obj)
			}

			s := runtime.NewScheme()
			utilruntime.Must(sourcev1.AddToScheme(s))
			builder := fakeclient.NewClientBuilder().WithScheme(s)
			if len(tt.dependencies) > 0 {
				builder.WithObjects(depObjs...)
			}

			r := &GitRepositoryReconciler{
				Client:  builder.Build(),
				Storage: storage,
				requeueDependency: dependencyInterval,
			}

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "reconcile-include",
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval: metav1.Duration{Duration: mockInterval},
				},
			}

			for i, incl := range tt.includes {
				incl := sourcev1.GitRepositoryInclude{
					GitRepositoryRef: meta.LocalObjectReference{Name: incl.name},
					FromPath:         incl.fromPath,
					ToPath:           incl.toPath,
				}
				tt.includes[i].fromPath = incl.GetFromPath()
				tt.includes[i].toPath = incl.GetToPath()
				obj.Spec.Include = append(obj.Spec.Include, incl)
			}

			tmpDir, err := ioutil.TempDir("", "include-")
			g.Expect(err).NotTo(HaveOccurred())

			var artifacts artifactSet
			got, err := r.reconcileInclude(ctx, obj, artifacts, tmpDir)
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			for _, i := range tt.includes {
				if i.toPath != "" {
					expect := g.Expect(filepath.Join(storage.BasePath, i.toPath))
					if i.shouldExist {
						expect.To(BeADirectory())
					} else {
						expect.NotTo(BeADirectory())
					}
				}
				if i.shouldExist {
					g.Expect(filepath.Join(storage.BasePath, i.toPath)).Should(BeADirectory())
				} else {
					g.Expect(filepath.Join(storage.BasePath, i.toPath)).ShouldNot(BeADirectory())
				}
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &GitRepositoryReconciler{
		Storage: storage,
	}

	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: sourcev1.GitRepositoryStatus{},
	}

	artifact := storage.NewArtifactFor(sourcev1.GitRepositoryKind, obj.GetObjectMeta(), "revision", "foo.txt")
	obj.Status.Artifact = &artifact

	got, err := r.reconcileDelete(ctx, obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(ctrl.Result{}))
	g.Expect(controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer)).To(BeFalse())
	g.Expect(obj.Status.Artifact).To(BeNil())

}

func TestGitRepositoryReconciler_verifyCommitSignature(t *testing.T) {
	tests := []struct {
		name             string
		secret           *corev1.Secret
		commit           git.Commit
		beforeFunc       func(obj *sourcev1.GitRepository)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Valid commit",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
			},
			commit: fake.NewCommit(true, "shasum"),
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: "head",
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, "ValidCommitSignature", "Verified signature of commit \"shasum\""),
			},
		},
		{
			name: "Invalid commit",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
			},
			commit: fake.NewCommit(false, "shasum"),
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: "head",
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "Commit signature verification failed: invalid signature"),
			},
		},
		{
			name: "Non existing secret",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: "head",
					SecretRef: meta.LocalObjectReference{
						Name: "none-existing",
					},
				}
			},
			want: ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "FailedToGetSecret", "PGP public keys secret error: secrets \"none-existing\" not found"),
			},
		},
		{
			name: "Nil verification in spec deletes SourceVerified condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
			},
			want:             ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{},
		},
		{
			name: "Empty verification mode in spec deletes SourceVerified condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: mockInterval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
			},
			want:             ctrl.Result{RequeueAfter: mockInterval},
			assertConditions: []metav1.Condition{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			s := runtime.NewScheme()
			utilruntime.Must(corev1.AddToScheme(s))

			builder := fakeclient.NewClientBuilder().WithScheme(s)
			if tt.secret != nil {
				builder.WithObjects(tt.secret)
			}

			r := &GitRepositoryReconciler{
				Client: builder.Build(),
			}

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-commit-",
					Generation:   1,
				},
				Status: sourcev1.GitRepositoryStatus{},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			got, err := r.verifyCommitSignature(logr.NewContext(ctx, log.NullLogger{}), obj, tt.commit)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

// TODO(hidde): move the below when more reconcilers have refactored tests

func TestMain(m *testing.M) {
	initTestTLS()

	utilruntime.Must(sourcev1.AddToScheme(scheme.Scheme))

	newTestEnv = testenv.NewTestEnvironment([]string{filepath.Join("..", "config", "crd", "bases")})

	storage, err := newTestStorage()
	if err != nil {
		panic(fmt.Sprintf("Failed to create a test storage: %v", err))
	}
	fmt.Println("Starting the test storage server")
	go serveTestStorage(storage)

	eventsHelper = controller.MakeEvents(newTestEnv, "test", nil)
	metricsHelper = controller.MustMakeMetrics(newTestEnv)

	if err := (&GitRepositoryReconciler{
		Client:  newTestEnv,
		Events:  eventsHelper,
		Metrics: metricsHelper,
		Storage: storage,
	}).SetupWithManager(newTestEnv); err != nil {
		panic(fmt.Sprintf("Failed to start GitRepositoryReconciler: %v", err))
	}

	go func() {
		fmt.Println("Starting the test environment manager")
		if err := newTestEnv.StartManager(ctx); err != nil {
			panic(fmt.Sprintf("Failed to start the test environment manager: %v", err))
		}
	}()
	<-newTestEnv.Manager.Elected()

	code := m.Run()

	fmt.Println("Stopping the test environment")
	if err := newTestEnv.Stop(); err != nil {
		panic(fmt.Sprintf("Failed to stop the test environment: %v", err))
	}

	os.Exit(code)
}

func initTestTLS() {
	var err error
	testTLSPublicKey, err = ioutil.ReadFile("testdata/certs/server.pem")
	if err != nil {
		panic(err)
	}
	testTLSPrivateKey, err = ioutil.ReadFile("testdata/certs/server-key.pem")
	if err != nil {
		panic(err)
	}
	testTLSCA, err = ioutil.ReadFile("testdata/certs/ca.pem")
	if err != nil {
		panic(err)
	}
}

func newTestStorage() (*Storage, error) {
	tmp, err := ioutil.TempDir("", "test-storage-")
	if err != nil {
		return nil, err
	}
	storage, err = NewStorage(tmp, "localhost:5050", time.Second*30)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	return storage, nil
}

func serveTestStorage(storage *Storage) error {
	fs := http.FileServer(http.Dir(storage.BasePath))
	handler := http.NewServeMux()
	handler.Handle("/", fs)
	return http.ListenAndServe(":5555", handler)
}

// helpers

func initGitRepo(server *gittestserver.GitServer, fixture, branch, repositoryPath string) (*gogit.Repository, error) {
	fs := memfs.New()
	repo, err := gogit.Init(memory.NewStorage(), fs)
	if err != nil {
		return nil, err
	}

	branchRef := plumbing.NewBranchReferenceName(branch)
	if err = repo.CreateBranch(&config.Branch{
		Name:   branch,
		Remote: gogit.DefaultRemoteName,
		Merge:  branchRef,
	}); err != nil {
		return nil, err
	}

	err = commitFromFixture(repo, fixture)
	if err != nil {
		return nil, err
	}

	if server.HTTPAddress() == "" {
		if err = server.StartHTTP(); err != nil {
			return nil, err
		}
		defer server.StopHTTP()
	}
	if _, err = repo.CreateRemote(&config.RemoteConfig{
		Name: gogit.DefaultRemoteName,
		URLs: []string{server.HTTPAddressWithCredentials() + repositoryPath},
	}); err != nil {
		return nil, err
	}

	if err = repo.Push(&gogit.PushOptions{
		RefSpecs: []config.RefSpec{"refs/heads/*:refs/heads/*"},
	}); err != nil {
		return nil, err
	}

	return repo, nil
}

func Test_commitFromFixture(t *testing.T) {
	g := NewWithT(t)

	repo, err := gogit.Init(memory.NewStorage(), memfs.New())
	g.Expect(err).ToNot(HaveOccurred())

	err = commitFromFixture(repo, "testdata/git/repository")
	g.Expect(err).ToNot(HaveOccurred())
}

func commitFromFixture(repo *gogit.Repository, fixture string) error {
	working, err := repo.Worktree()
	if err != nil {
		return err
	}
	fs := working.Filesystem

	if err = filepath.Walk(fixture, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fs.MkdirAll(fs.Join(path[len(fixture):]), info.Mode())
		}

		fileBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		ff, err := fs.Create(path[len(fixture):])
		if err != nil {
			return err
		}
		defer ff.Close()

		_, err = ff.Write(fileBytes)
		return err
	}); err != nil {
		return err
	}

	_, err = working.Add(".")
	if err != nil {
		return err
	}

	if _, err = working.Commit("Fixtures from "+fixture, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "Jane Doe",
			Email: "jane@example.com",
			When:  time.Now(),
		},
	}); err != nil {
		return err
	}

	return nil
}

func remoteBranchForHead(repo *gogit.Repository, head *plumbing.Reference, branch string) error {
	refSpec := fmt.Sprintf("%s:refs/heads/%s", head.Name(), branch)
	return repo.Push(&gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(refSpec)},
		Force:      true,
	})
}

func remoteTagForHead(repo *gogit.Repository, head *plumbing.Reference, tag string) error {
	if _, err := repo.CreateTag(tag, head.Hash(), &gogit.CreateTagOptions{
		Message: tag,
	}); err != nil {
		return err
	}
	refSpec := fmt.Sprintf("refs/tags/%[1]s:refs/tags/%[1]s", tag)
	return repo.Push(&gogit.PushOptions{
		RefSpecs: []config.RefSpec{config.RefSpec(refSpec)},
	})
}
