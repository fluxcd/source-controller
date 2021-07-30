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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/pkg/git"
)

var (
	testGitImplementations = []string{sourcev1.GoGitImplementation, sourcev1.LibGit2Implementation}
)

func TestGitRepositoryReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(server.Root())
	server.AutoCreate()
	g.Expect(server.StartHTTP()).To(Succeed())
	defer server.StopHTTP()

	repoPath := "/test.git"
	_, err = initGitRepo(server, "testdata/git/repository", git.DefaultBranch, repoPath)
	g.Expect(err).NotTo(HaveOccurred())

	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "gitrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.GitRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      server.HTTPAddress() + repoPath,
		},
	}
	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for GitRepository to be Ready
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		if !conditions.IsReady(obj) || obj.Status.Artifact == nil {
			return false
		}
		readyCondition := conditions.Get(obj, meta.ReadyCondition)
		return obj.Generation == readyCondition.ObservedGeneration &&
			obj.Generation == obj.Status.ObservedGeneration
	}, timeout).Should(BeTrue())

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for GitRepository to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
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
			name:     "HTTP without secretRef makes ArtifactOutdated=True",
			protocol: "http",
			want:     ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'master/<commit>'"),
			},
		},
		{
			name:     "HTTP with Basic Auth secret makes ArtifactOutdated=True",
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
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'master/<commit>'"),
			},
		},
		{
			name:     "HTTPS with CAFile secret makes ArtifactOutdated=True",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": tlsCA,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'master/<commit>'"),
			},
		},
		{
			name:                  "HTTPS with invalid CAFile secret makes CheckoutFailed=True and returns error",
			skipForImplementation: sourcev1.LibGit2Implementation,
			protocol:              "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
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
				*conditions.TrueCondition(sourcev1.CheckoutFailedCondition, sourcev1.GitOperationFailedReason, "x509: certificate signed by unknown authority"),
			},
		},
		{
			name:                  "HTTPS with invalid CAFile secret makes CheckoutFailed=True and returns error",
			skipForImplementation: sourcev1.GoGitImplementation,
			protocol:              "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
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
				*conditions.TrueCondition(sourcev1.CheckoutFailedCondition, sourcev1.GitOperationFailedReason, "Failed to checkout and determine revision: unable to clone '<url>', error: Certificate"),
			},
		},
		{
			name:     "SSH with private key secret makes ArtifactOutdated=True",
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
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'master/<commit>'"),
			},
		},
		{
			name:     "SSH with password protected private key secret makes ArtifactOutdated=True",
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
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision 'master/<commit>'"),
			},
		},
		{
			name:     "Include get failure makes CheckoutFailed=True and returns error",
			protocol: "http",
			server: options{
				username: "git",
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "non-existing"}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.CheckoutFailedCondition, "AuthenticationFailed", "Failed to get secret '/non-existing': secrets \"non-existing\" not found"),
			},
		},
	}

	for _, tt := range tests {
		obj := &sourcev1.GitRepository{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "auth-strategy-",
			},
			Spec: sourcev1.GitRepositorySpec{
				Interval: metav1.Duration{Duration: interval},
				Timeout:  &metav1.Duration{Duration: interval},
			},
		}

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

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			if secret != nil {
				builder.WithObjects(secret.DeepCopy())
			}

			r := &GitRepositoryReconciler{
				Client:  builder.Build(),
				Storage: testStorage,
			}

			for _, i := range testGitImplementations {
				t.Run(i, func(t *testing.T) {
					g := NewWithT(t)

					if tt.skipForImplementation == i {
						t.Skipf("Skipped for Git implementation %q", i)
					}

					tmpDir, err := os.MkdirTemp("", "auth-strategy-")
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
					dlog := log.NewDelegatingLogSink(log.NullLogSink{})
					nullLogger := logr.New(dlog)
					got, err := r.reconcileSource(logr.NewContext(ctx, nullLogger), obj, &artifact, tmpDir)
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
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "master/<commit>",
		},
		{
			name: "Branch",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "staging/<commit>",
		},
		{
			name: "Tag",
			reference: &sourcev1.GitRepositoryRef{
				Tag: "v0.1.0",
			},
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "v0.1.0/<commit>",
		},
		{
			name: "Branch commit",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
				Commit: "<commit>",
			},
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "staging/<commit>",
		},
		{
			name: "SemVer",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "*",
			},
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "v2.0.0/<commit>",
		},
		{
			name: "SemVer range",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "<v0.2.1",
			},
			want:         ctrl.Result{RequeueAfter: interval},
			wantRevision: "0.2.0/<commit>",
		},
		{
			name: "SemVer prerelease",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: ">=1.0.0-0 <1.1.0-0",
			},
			wantRevision: "v1.0.0-alpha/<commit>",
			want:         ctrl.Result{RequeueAfter: interval},
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
		Storage: testStorage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: interval},
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

					tmpDir, err := os.MkdirTemp("", "checkout-strategy-")
					g.Expect(err).NotTo(HaveOccurred())
					defer os.RemoveAll(tmpDir)

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
						g.Expect(conditions.IsTrue(obj, sourcev1.ArtifactOutdatedCondition)).To(BeTrue())
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
			name: "Archiving artifact to storage makes Ready=True",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).To(Equal("f9955588f6aeed7be9b1ef15cd2ddac47bb53291"))
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'main/revision'"),
			},
		},
		{
			name: "Spec ignore overwrite is taken into account",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Ignore = pointer.StringPtr("!**.txt\n")
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository, artifact sourcev1.Artifact) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Checksum).To(Equal("542a8ad0171118a3249e8c531c598b898defd742"))
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Stored artifact for revision 'main/revision'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := &GitRepositoryReconciler{
				Storage: testStorage,
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

			artifact := testStorage.NewArtifactFor(obj.Kind, obj, "main/revision", "checksum.tar.gz")

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

	server, err := testserver.NewTempArtifactServer()
	g.Expect(err).NotTo(HaveOccurred())
	storage, err := newTestStorage(server.HTTPServer)
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(testStorage.BasePath)

	dependencyInterval := 5 * time.Second

	type dependency struct {
		name         string
		withArtifact bool
		conditions   []metav1.Condition
	}

	type include struct {
		name        string
		fromPath    string
		toPath      string
		shouldExist bool
	}

	tests := []struct {
		name             string
		dependencies     []dependency
		includes         []include
		beforeFunc       func(obj *sourcev1.GitRepository)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "New includes make ArtifactOutdated=True",
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
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "IncludeChange", "Included artifacts differ from last observed includes"),
			},
		},
		{
			name: "Include get failure makes IncludeUnavailable=True and returns error",
			includes: []include{
				{name: "a", toPath: "a/"},
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "NotFound", "Could not get resource for include \"a\": gitrepositories.source.toolkit.fluxcd.io \"a\" not found"),
			},
		},
		{
			name: "Include without an artifact makes IncludeUnavailable=True",
			dependencies: []dependency{
				{
					name:         "a",
					withArtifact: false,
					conditions: []metav1.Condition{
						*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "Foo", "foo unavailable"),
					},
				},
			},
			includes: []include{
				{name: "a", toPath: "a/"},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "NoArtifact", "No artifact available for include \"a\""),
			},
		},
		{
			name: "Invalid FromPath makes IncludeUnavailable=True and returns error",
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
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "CopyFailure", "unpack/path: no such file or directory"),
			},
		},
		{
			name: "Outdated IncludeUnavailable is removed",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NoArtifact", "")
			},
			want:             ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{},
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

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			if len(tt.dependencies) > 0 {
				builder.WithObjects(depObjs...)
			}

			r := &GitRepositoryReconciler{
				Client:        builder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				// Events: helper.Events{
				// 	Scheme:        testEnv.GetScheme(),
				// 	EventRecorder: record.NewFakeRecorder(32),
				// },
				Storage:           storage,
				requeueDependency: dependencyInterval,
			}

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name: "reconcile-include",
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
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

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			tmpDir, err := os.MkdirTemp("", "include-")
			g.Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			var artifacts artifactSet
			got, err := r.reconcileInclude(ctx, obj, artifacts, tmpDir)
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			for _, i := range tt.includes {
				if i.toPath != "" {
					expect := g.Expect(filepath.Join(testStorage.BasePath, i.toPath))
					if i.shouldExist {
						expect.To(BeADirectory())
					} else {
						expect.NotTo(BeADirectory())
					}
				}
				if i.shouldExist {
					g.Expect(filepath.Join(testStorage.BasePath, i.toPath)).Should(BeADirectory())
				} else {
					g.Expect(filepath.Join(testStorage.BasePath, i.toPath)).ShouldNot(BeADirectory())
				}
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &GitRepositoryReconciler{
		Storage: testStorage,
	}

	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: sourcev1.GitRepositoryStatus{},
	}

	artifact := testStorage.NewArtifactFor(sourcev1.GitRepositoryKind, obj.GetObjectMeta(), "revision", "foo.txt")
	obj.Status.Artifact = &artifact

	got, err := r.reconcileDelete(ctx, obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(ctrl.Result{}))
	g.Expect(controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer)).To(BeFalse())
	g.Expect(obj.Status.Artifact).To(BeNil())
}

// func TestGitRepositoryReconciler_verifyCommitSignature(t *testing.T) {
// 	tests := []struct {
// 		name             string
// 		secret           *corev1.Secret
// 		commit           git.Commit
// 		beforeFunc       func(obj *sourcev1.GitRepository)
// 		want             ctrl.Result
// 		wantErr          bool
// 		assertConditions []metav1.Condition
// 	}{
// 		{
// 			name: "Valid commit makes SourceVerifiedCondition=True",
// 			secret: &corev1.Secret{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Name: "existing",
// 				},
// 			},
// 			commit: fake.NewCommit(true, "shasum"),
// 			beforeFunc: func(obj *sourcev1.GitRepository) {
// 				obj.Spec.Interval = metav1.Duration{Duration: interval}
// 				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
// 					Mode: "head",
// 					SecretRef: meta.LocalObjectReference{
// 						Name: "existing",
// 					},
// 				}
// 			},
// 			want: ctrl.Result{RequeueAfter: interval},
// 			assertConditions: []metav1.Condition{
// 				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "Verified signature of commit \"shasum\""),
// 			},
// 		},
// 		{
// 			name: "Invalid commit makes SourceVerifiedCondition=False and returns error",
// 			secret: &corev1.Secret{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Name: "existing",
// 				},
// 			},
// 			commit: fake.NewCommit(false, "shasum"),
// 			beforeFunc: func(obj *sourcev1.GitRepository) {
// 				obj.Spec.Interval = metav1.Duration{Duration: interval}
// 				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
// 					Mode: "head",
// 					SecretRef: meta.LocalObjectReference{
// 						Name: "existing",
// 					},
// 				}
// 			},
// 			wantErr: true,
// 			assertConditions: []metav1.Condition{
// 				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, meta.FailedReason, "Signature verification of commit \"shasum\" failed: invalid signature"),
// 			},
// 		},
// 		{
// 			name: "Secret get failure makes SourceVerified=False and returns error",
// 			beforeFunc: func(obj *sourcev1.GitRepository) {
// 				obj.Spec.Interval = metav1.Duration{Duration: interval}
// 				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
// 					Mode: "head",
// 					SecretRef: meta.LocalObjectReference{
// 						Name: "none-existing",
// 					},
// 				}
// 			},
// 			wantErr: true,
// 			assertConditions: []metav1.Condition{
// 				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, meta.FailedReason, "PGP public keys secret error: secrets \"none-existing\" not found"),
// 			},
// 		},
// 		{
// 			name: "Nil verification in spec deletes SourceVerified condition",
// 			beforeFunc: func(obj *sourcev1.GitRepository) {
// 				obj.Spec.Interval = metav1.Duration{Duration: interval}
// 				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
// 			},
// 			want:             ctrl.Result{RequeueAfter: interval},
// 			assertConditions: []metav1.Condition{},
// 		},
// 		{
// 			name: "Empty verification mode in spec deletes SourceVerified condition",
// 			beforeFunc: func(obj *sourcev1.GitRepository) {
// 				obj.Spec.Interval = metav1.Duration{Duration: interval}
// 				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{}
// 				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
// 			},
// 			want:             ctrl.Result{RequeueAfter: interval},
// 			assertConditions: []metav1.Condition{},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			g := NewWithT(t)

// 			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
// 			if tt.secret != nil {
// 				builder.WithObjects(tt.secret)
// 			}

// 			r := &GitRepositoryReconciler{
// 				Client: builder.Build(),
// 			}

// 			obj := &sourcev1.GitRepository{
// 				ObjectMeta: metav1.ObjectMeta{
// 					GenerateName: "verify-commit-",
// 					Generation:   1,
// 				},
// 				Status: sourcev1.GitRepositoryStatus{},
// 			}

// 			if tt.beforeFunc != nil {
// 				tt.beforeFunc(obj)
// 			}

// 			got, err := r.verifyCommitSignature(logr.NewContext(ctx, log.NullLogger{}), obj, tt.commit)
// 			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
// 			g.Expect(err != nil).To(Equal(tt.wantErr))
// 			g.Expect(got).To(Equal(tt.want))
// 		})
// 	}
// }

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

		fileBytes, err := os.ReadFile(path)
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
		// Not setting this seems to make things flaky
		//		Expected success, but got an error:
		//			<*errors.errorString | 0xc0000f6350>: {
		//				s: "tagger field is required",
		//			}
		//			tagger field is required
		Tagger: &object.Signature{
			Name:  "Jane Doe",
			Email: "jane@example.com",
			When:  time.Now(),
		},
		Message: tag,
	}); err != nil {
		return err
	}
	refSpec := fmt.Sprintf("refs/tags/%[1]s:refs/tags/%[1]s", tag)
	return repo.Push(&gogit.PushOptions{
		RefSpecs: []config.RefSpec{config.RefSpec(refSpec)},
	})
}
