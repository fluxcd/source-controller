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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	. "github.com/onsi/gomega"
	sshtestdata "golang.org/x/crypto/ssh/testdata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kstatus "github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/github"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	serror "github.com/werf/nelm-source-controller/internal/error"
	"github.com/werf/nelm-source-controller/internal/features"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
)

const (
	encodedCommitFixture = `tree 35f0b28987e60d4b8dec1f707fd07fef5ad84abc
parent 8b52742dbc848eb0975e62ae00fbfa4f8108e835
author Sanskar Jaiswal <jaiswalsanskar078@gmail.com> 1691045123 +0530
committer Sanskar Jaiswal <jaiswalsanskar078@gmail.com> 1691068951 +0530

git/e2e: disable CGO while running e2e tests

Disable CGO for Git e2e tests as it was originially required because of
our libgit2 client. Since we no longer maintain a libgit2 client, there
is no need to run the tests with CGO enabled.

Signed-off-by: Sanskar Jaiswal <jaiswalsanskar078@gmail.com>
`

	malformedEncodedCommitFixture = `parent eb167bc68d0a11530923b1f24b4978535d10b879
author Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300
committer Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300

Update containerd and runc to fix CVEs

Signed-off-by: Stefan Prodan <stefan.prodan@gmail.com>
`
	signatureCommitFixture = `-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEEOxEY0f3iSZ5rKQ+vWYLQJ5wif/0FAmTLqnEACgkQWYLQJ5wi
f/1mYw/+LRttvfPrfYl7ASUBGYSQuDzjeold8OO1LpmwjrKPpX4ivZbXHh+lJF0F
fqudKuJfJzeQCHsMZjnfgvXHd2VvxPh1jX6h3JLuNu7d4g1DtNQsKJtsLx7JW99X
J9Bb1xj0Ghh2PkrWEB9vpw+uZz4IhFrB+DNNLRNBkon3etrS1q57q8dhQFIhLI1y
ij3rq3kFHjrNNdokIv2ujyVJtWgy2fK2ELW5v2dznpykOo7hQEKgtOIHPBzGBFT0
dUFjB99Qy4Qgjh3vWaY4fZ3u/vhp3swmw91OlDkFeyndWjDSZhzYnb7wY+U6z35C
aU4Gzc71CquSd/nTdOEkpuolBVWV5cBkM+Nxi8jtVGBeDDFE49j27a3lQ3+qtT7/
q4FCe5Jw3GSOJvaLBLGmYVn9fc49t/28b5tkGtCHs3ATpsJohzELEIiDP90Me7hQ
Joks3ML38T4J/zZ4/ObbVMkrCEATYe3r1Ep7+e6VmOG9iTg0JIexexddjHX26Tgu
iuVP2GD/8PceqgNW/LPX84Ub32WTKPZJg+NyliDjH5QOvmguK1dRtSb/9eyYcoSF
Fkf0HcgG5jOk0OZJv0QcqXd9PhB4oXeuXgGszo9M+fhr3nWvEooAJtIyLtVtt/u2
rNNB7xkZ1uWx+52w9RG2gmZh+LaESwd1rNXgUFLNBebNN3jNzsA=
=73xf
-----END PGP SIGNATURE-----`

	encodedTagFixture = `object 11525516bd55152ce68848bb14680aad43f18479
type commit
tag v0.1.0
tagger Sanskar Jaiswal <jaiswalsanskar078@gmail.com> 1691132850 +0530

v0.1.0
`

	malformedEncodedTagFixture = `object 11525516bd55152ce68848bb14680aad43f18479
tagger Sanskar Jaiswal <jaiswalsanskar078@gmail.com> 1691132850 +0530

v0.1.0
`

	signatureTagFixture = `-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEEOxEY0f3iSZ5rKQ+vWYLQJ5wif/0FAmTMo7IACgkQWYLQJ5wi
f/1uUQ/9F70u8LZZQ3+U2vuYQ8fyVp/AV5h5zwxK5UlkR1crB0gSpdaiIxMMQRc8
4QQIqCXloSHherUu9SPbDe9Qmr0JL8a57XqThjUSa52IYMDVos9sYwViJit+xGyz
HDot2nQ8MAqkDaiuwAnTqOyTPA89U36lGV/X/25mYxAuED+8xFx1OfvjGkX2eMEr
peWJ8VEfdFr2OmWwFceh6iF/izIaZGttwCyNy4BIh2W0GvUtQAxzqF4IzUvwfJU/
bgARaHKQhWqFhDNImttsqJBweWavEDDmUgNg80c3cUZKqBtAjElToP9gis/SnPH5
zaCAH66OzyKIhn6lde7KpOzyqbOyzddTa8SKkAAHyO7onukOktV8W9toeAxlF20q
Bw0MZGzAGisF8EK1HVv8UzrW9vAwdJN/yDIHWkjaeHr2FHmeV3a2QxH9PdwbE3tI
B21TCVULJuM8oR0ZG62xzg5ba5HiZMiilNMJdrBfjk5xYGk3LQU1gB4FVYa7yTsN
YfAokYtUIG187Qb8vPr1P95TzZxKdb7r/PAKEbGPro5D2Rri8OnxO/OaXG/giWS5
5gRGmsQjvMsbzE/2PVc9+jshtZM49xL9H3DMjAWtO6MFbOqGqdi4MBa0T4qj6sZz
AbSLuRIBpXDES86faDXLRmufc95+iA/fh7W23G6vmd+SjXnCcHc=
=o4nf
-----END PGP SIGNATURE-----
`

	armoredKeyRingFixture = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGQmiZ0BEACwsubUFoWtp6iJDK9oUN4RhPS0bAKpcRTa7P/rTCD/MbTMYdWC
4vod3FMm4+rNF0SESxY67MGmR4M3dSyOZkCijqHm9jDVOvN847LOl5bntkm8Euxm
LkpfsBWng09+gtfwuKxOxPMY017D1jM23OGbrqznHaokerFeDp9sJf1C7Z9jVf39
oB/MF0bMdUJuxFFBdpoI73DORlAVUI14mfDbFj7v02Spkv1hqS2LtJ/Jl4QR/Vw4
mR71aFmGFWqLBlkUOjJ2SZGkCmF/qbUdLmVb7yZUtqtua4DVkBPTORfOMhGDbrME
Nmb6Ft5neZwU0ETsT/oc6Np+PDFSUDBxu0CbKG6bw7N2y8RfiVJTaoNLFoFGV5dA
K8OpyTxU4IEPDMpkWs7tpRxPCC02uCfyqlvdF4EURXYXTj54DDLOGQjoqB+iGtVi
y2dQ4cuNhfuIFCFTA16s41DwmB0fQuOg3yfPPo7+jUefD+iAt3CZ9Guvu5+/mGyq
KxSBBRFHc8ED/L7JLPMU6tZglaPch9P4H6Fi2swDryyZQn/a2kYanEh9v1wL94L4
3gUdjIYP8kjfg7nnS2FX9hl5FtPeM3jvnWjfv9jR+c8HWQZY2wM3Rj5iulu70K2U
pkdRUN0p2D5+Kq6idNreNoPlpQGoUOYrtAfOwtDFgMwuOZ78XkSIbFhtgwARAQAB
tEVTYW5za2FyIEphaXN3YWwgKEdpdEh1YiBHUEcgc2lnaW5nIGtleSkgPGphaXN3
YWxzYW5za2FyMDc4QGdtYWlsLmNvbT6JAk4EEwEIADgWIQQ7ERjR/eJJnmspD69Z
gtAnnCJ//QUCZCaJnQIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRBZgtAn
nCJ//dF4D/0Tl5Wre6KrZvjDs5loulhN8YMYb63jr+x1eVkpMpta51XvZvkZFoiY
9T4MQX+qgAkTrUJsxgWUwtVtDfmbyLXodDRS6JUbCRiMu12VD7mNT+lUfuhR2sJv
rHZoolQp7X4DTea1R64PcttfmlGO2pUNpGNmhojO0PahXqOCHmEUWBJQhI8RvOcs
zRjEzDcAcEgtMGzamq6DR54YxyzGE8V9b5WD/elmEXM6uWW+CkfX8WskKbLdRY0t
+GQ1pOtf3tKxD46I3LIsUEwbyh4Dv4vJbZmyxjI+FKbSCW5tMrz/ZWrPNl0m+pDI
Yn0+GWed2pgTMFh3VAhYCyIVugKynlaToH+D2z3DnuEp3Jfs+b1BdirS/PW79tW7
rjCJzqofF2UPyK0mzdYL+P3k9Hip5J0bCGoeMdCLsP5fYq3Y1YS4bH4JkDm52y+r
y89AH4LHHQt+A7w19I+6M2jmcNnDUMrpuSo84GeoM59O3fU7hLCC1Jx4hj7EBRrb
QzY5FInrE/WTcgFRljK46zhW4ybmfak/xJV654UqJCDWlVbc68D8JrKNQOj7gdPs
zh1+m2pFDEhWZkaFtQbSEpXMIJ9DsCoyQL4Knl+89VxHsrIyAJsmGb3V8xvtv5w9
QuWtsDnYbvDHtTpu1NZChVrnr/l1k3C2fcLhV1s583AvhGMkbgSXkQ==
=Tdjz
-----END PGP PUBLIC KEY BLOCK-----
`
)

func TestGitRepositoryReconciler_deleteBeforeFinalizer(t *testing.T) {
	g := NewWithT(t)

	namespaceName := "gitrepo-" + randStringRunes(5)
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}
	g.Expect(k8sClient.Create(ctx, namespace)).ToNot(HaveOccurred())
	t.Cleanup(func() {
		g.Expect(k8sClient.Delete(ctx, namespace)).NotTo(HaveOccurred())
	})

	gitRepo := &sourcev1.GitRepository{}
	gitRepo.Name = "test-gitrepo"
	gitRepo.Namespace = namespaceName
	gitRepo.Spec = sourcev1.GitRepositorySpec{
		Interval: metav1.Duration{Duration: interval},
		URL:      "https://example.com",
	}
	// Add a test finalizer to prevent the object from getting deleted.
	gitRepo.SetFinalizers([]string{"test-finalizer"})
	g.Expect(k8sClient.Create(ctx, gitRepo)).NotTo(HaveOccurred())
	// Add deletion timestamp by deleting the object.
	g.Expect(k8sClient.Delete(ctx, gitRepo)).NotTo(HaveOccurred())

	r := &GitRepositoryReconciler{
		Client:        k8sClient,
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}
	// NOTE: Only a real API server responds with an error in this scenario.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gitRepo)})
	g.Expect(err).NotTo(HaveOccurred())
}

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

	origObj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "gitrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.GitRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      server.HTTPAddress() + repoPath,
		},
	}
	obj := origObj.DeepCopy()
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
	waitForSourceReadyWithArtifact(ctx, g, obj)

	// Check if the object status is valid.
	condns := &conditionscheck.Conditions{NegativePolarity: gitRepositoryReadyCondition.NegativePolarity}
	checker := conditionscheck.NewChecker(testEnv.Client, condns)
	checker.WithT(g).CheckErr(ctx, obj)

	// kstatus client conformance check.
	u, err := patch.ToUnstructured(obj)
	g.Expect(err).ToNot(HaveOccurred())
	res, err := kstatus.Compute(u)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Status).To(Equal(kstatus.CurrentStatus))

	// Patch the object with reconcile request annotation.
	patchHelper, err := patch.NewHelper(obj, testEnv.Client)
	g.Expect(err).ToNot(HaveOccurred())
	annotations := map[string]string{
		meta.ReconcileRequestAnnotation: "now",
	}
	obj.SetAnnotations(annotations)
	g.Expect(patchHelper.Patch(ctx, obj)).ToNot(HaveOccurred())
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return obj.Status.LastHandledReconcileAt == "now"
	}, timeout).Should(BeTrue())

	g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for GitRepository to be deleted
	waitForSourceDeletion(ctx, g, obj)

	// Check if a suspended object gets deleted.
	obj = origObj.DeepCopy()
	testSuspendedObjectDeleteWithArtifact(ctx, g, obj)
}

func TestGitRepositoryReconciler_reconcileSource_emptyRepository(t *testing.T) {
	g := NewWithT(t)

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(server.Root())
	server.AutoCreate()
	g.Expect(server.StartHTTP()).To(Succeed())
	defer server.StopHTTP()

	obj := &sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "empty-",
			Generation:   1,
		},
		Spec: sourcev1.GitRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			Timeout:  &metav1.Duration{Duration: timeout},
			URL:      server.HTTPAddress() + "/test.git",
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.GitRepository{})

	r := &GitRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
	}

	g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
	defer func() {
		g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
	}()

	var commit git.Commit
	var includes artifactSet
	sp := patch.NewSerialPatcher(obj, r.Client)

	got, err := r.reconcileSource(context.TODO(), sp, obj, &commit, &includes, t.TempDir())
	assertConditions := []metav1.Condition{
		*conditions.TrueCondition(sourcev1.FetchFailedCondition, "EmptyGitRepository", "git repository is empty"),
	}
	g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(assertConditions))
	g.Expect(err).To(HaveOccurred())
	g.Expect(got).To(Equal(sreconcile.ResultEmpty))
	g.Expect(commit).ToNot(BeNil())
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
		name             string
		protocol         string
		server           options
		secret           *corev1.Secret
		beforeFunc       func(obj *sourcev1.GitRepository)
		secretFunc       func(secret *corev1.Secret, baseURL string)
		middlewareFunc   gittestserver.HTTPMiddleware
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name:     "HTTP without secretRef makes Reconciling=True",
			protocol: "http",
			want:     sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			name:     "HTTP with Basic Auth secret makes Reconciling=True",
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
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			name:     "HTTPS with mutual TLS makes Reconciling=True",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mtls-certs",
				},
				Data: map[string][]byte{
					"ca.crt":  tlsCA,
					"tls.crt": clientPublicKey,
					"tls.key": clientPrivateKey,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "mtls-certs"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			name:     "HTTPS with mutual TLS and invalid private key makes CheckoutFailed=True and returns error",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-mtls-certs",
				},
				Data: map[string][]byte{
					"ca.crt":  tlsCA,
					"tls.crt": clientPublicKey,
					"tls.key": []byte("invalid"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "invalid-mtls-certs"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "tls: failed to find any PEM data in key input"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
		{
			name:     "HTTPS with CAFile secret makes Reconciling=True",
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
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			name:     "HTTPS with CAFile secret with both ca.crt and caFile keys makes Reconciling=True and ignores caFile",
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
					"ca.crt": tlsCA,
					"caFile": []byte("invalid"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "ca-file"}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			name:     "HTTPS with invalid CAFile secret makes CheckoutFailed=True and returns error",
			protocol: "https",
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
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				// The expected error messages may differ when in darwin. In some cases it will match the
				// error message expected in linux: "x509: certificate signed by unknown authority". In
				// other cases it may get "x509: “example.com” certificate is not standards compliant" instead.
				//
				// Trimming the expected error message for consistent results.
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "x509: "),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
		{
			name:     "mTLS GitHub App without ca.crt makes FetchFailed=True",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "gh-app-no-ca"},
				Data: map[string][]byte{
					github.KeyAppID:             []byte("123"),
					github.KeyAppInstallationID: []byte("456"),
					github.KeyAppPrivateKey:     sshtestdata.PEMBytes["rsa"],
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "gh-app-no-ca"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingWithRetryReason, "foo")
			},
			secretFunc: func(secret *corev1.Secret, baseURL string) {
				secret.Data[github.KeyAppBaseURL] = []byte(baseURL + "/api/v3")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				// should record a FetchFailedCondition due to TLS handshake
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "x509: "),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingWithRetryReason, "foo"),
			},
		},
		{
			name:     "mTLS GitHub App with ca.crt makes Reconciling=True",
			protocol: "https",
			server: options{
				publicKey:  tlsPublicKey,
				privateKey: tlsPrivateKey,
				ca:         tlsCA,
				username:   github.AccessTokenUsername,
				password:   "some-enterprise-token",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "gh-app-ca"},
				Data: map[string][]byte{
					github.KeyAppID:             []byte("123"),
					github.KeyAppInstallationID: []byte("456"),
					github.KeyAppPrivateKey:     sshtestdata.PEMBytes["rsa"],
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "gh-app-ca"}
			},
			secretFunc: func(secret *corev1.Secret, baseURL string) {
				secret.Data[github.KeyAppBaseURL] = []byte(baseURL + "/api/v3")
				secret.Data["ca.crt"] = tlsCA
			},
			middlewareFunc: func(handler http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/api/v3/app/installations/") {
						w.WriteHeader(http.StatusOK)
						tok := &github.AppToken{
							Token:     "some-enterprise-token",
							ExpiresAt: time.Now().Add(time.Hour),
						}
						_ = json.NewEncoder(w).Encode(tok)
					}
					handler.ServeHTTP(w, r)
				})
			},
			wantErr: false,
			want:    sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		// TODO: Add test case for HTTPS with bearer token auth secret. It
		// depends on gitkit to have support for bearer token based
		// authentication.
		{
			name:     "SSH with private key secret makes Reconciling=True",
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
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>"),
			},
		},
		{
			name:     "SSH with password protected private key secret makes Reconciling=True",
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
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
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
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret '/non-existing': secrets \"non-existing\" not found"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
		{
			name:     "Existing artifact makes ArtifactOutdated=True",
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
				obj.Status = sourcev1.GitRepositoryStatus{
					Artifact: &meta.Artifact{
						Revision: "staging/some-revision",
						Path:     randStringRunes(10),
					},
				}
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new upstream revision 'master@sha1:<commit>'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new upstream revision 'master@sha1:<commit>'"),
			},
		},
		{
			// This test is only for verifying the failure state when using
			// provider auth. Protocol http is used for simplicity.
			name:     "github provider without secret ref makes FetchFailed=True",
			protocol: "http",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.InvalidProviderConfigurationReason, "secretRef with github app data must be specified when provider is set to github"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
		{
			// This test is only for verifying the failure state when using
			// provider auth. Protocol http is used for simplicity.
			name:     "empty provider with github app data in secret makes FetchFailed=True",
			protocol: "http",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "github-app-secret",
				},
				Data: map[string][]byte{
					github.KeyAppID: []byte("1111"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "github-app-secret"}
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.InvalidProviderConfigurationReason, "secretRef '/github-app-secret' has github app data but provider is not set to github"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
		{
			// This test is only for verifying the failure state when using
			// provider auth. Protocol http is used for simplicity.
			name:     "github provider without github app data in secret makes FetchFailed=True",
			protocol: "http",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "github-basic-auth",
				},
				Data: map[string][]byte{
					"username": []byte("abc"),
					"password": []byte("1234"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: "github-basic-auth"}
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				conditions.MarkReconciling(obj, meta.ProgressingReason, "foo")
				conditions.MarkUnknown(obj, meta.ReadyCondition, meta.ProgressingReason, "foo")
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.InvalidProviderConfigurationReason, "secretRef with github app data must be specified when provider is set to github"),
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "foo"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "foo"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
					Generation:   1,
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			server, err := gittestserver.NewTempGitServer()
			g.Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(server.Root())
			server.AutoCreate()

			if tt.middlewareFunc != nil {
				server.AddHTTPMiddlewares(tt.middlewareFunc)
			}

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
					knownHosts, err := ssh.ScanHostKey(u.Host, timeout, git.HostKeyAlgos, false)
					g.Expect(err).NotTo(HaveOccurred())
					secret.Data["known_hosts"] = knownHosts
				}
			default:
				t.Fatalf("unsupported protocol %q", tt.protocol)
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			if tt.secretFunc != nil {
				tt.secretFunc(secret, server.HTTPAddress())
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.GitRepository{})

			if secret != nil {
				clientBuilder.WithObjects(secret.DeepCopy())
			}

			r := &GitRepositoryReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}

			tmpDir := t.TempDir()

			head, _ := localRepo.Head()
			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<commit>", head.Hash().String())
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", obj.Spec.URL)
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			var commit git.Commit
			var includes artifactSet
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileSource(context.TODO(), sp, obj, &commit, &includes, tmpDir)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(commit).ToNot(BeNil())

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestGitRepositoryReconciler_getAuthOpts_provider(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		secret     *corev1.Secret
		beforeFunc func(obj *sourcev1.GitRepository)
		wantErr    string
	}{
		{
			name: "azure provider",
			url:  "https://dev.azure.com/foo/bar/_git/baz",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderAzure
			},
			wantErr: "ManagedIdentityCredential",
		},
		{
			name: "azure provider with service account and feature gate for object-level identity disabled",
			url:  "https://dev.azure.com/foo/bar/_git/baz",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderAzure
				obj.Spec.ServiceAccountName = "azure-sa"
			},
			wantErr: auth.FeatureGateObjectLevelWorkloadIdentity,
		},
		{
			name: "github provider with no secret ref",
			url:  "https://github.com/org/repo.git",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
			},
			wantErr: "secretRef with github app data must be specified when provider is set to github",
		},
		{
			name: "github provider with github app data in secret",
			url:  "https://example.com/org/repo",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "githubAppSecret",
				},
				Data: map[string][]byte{
					github.KeyAppID:             []byte("123"),
					github.KeyAppInstallationID: []byte("456"),
					github.KeyAppPrivateKey:     []byte("abc"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "githubAppSecret",
				}
			},
			wantErr: "Key must be a PEM encoded PKCS1 or PKCS8 key",
		},
		{
			name: "generic provider with github app data in secret",
			url:  "https://example.com/org/repo",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "githubAppSecret",
				},
				Data: map[string][]byte{
					github.KeyAppID: []byte("123"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGeneric
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "githubAppSecret",
				}
			},
			wantErr: "secretRef '/githubAppSecret' has github app data but provider is not set to github",
		},
		{
			name: "github provider with basic auth secret",
			url:  "https://github.com/org/repo.git",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "basic-auth-secret",
				},
				Data: map[string][]byte{
					"username": []byte("abc"),
					"password": []byte("1234"),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGitHub
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "basic-auth-secret",
				}
			},
			wantErr: "secretRef with github app data must be specified when provider is set to github",
		},
		{
			name: "generic provider",
			url:  "https://example.com/org/repo",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Provider = sourcev1.GitProviderGeneric
			},
		},
		{
			name: "secret ref defined for non existing secret",
			url:  "https://github.com/org/repo.git",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: "authSecret",
				}
			},
			wantErr: "failed to get secret '/authSecret': secrets \"authSecret\" not found",
		},
		{
			url:  "https://example.com/org/repo",
			name: "no provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.GitRepository{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret)
			}

			obj := &sourcev1.GitRepository{}
			r := &GitRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        clientBuilder.Build(),
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}

			url, err := url.Parse(tt.url)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			opts, err := r.getAuthOpts(ctx, obj, *url, nil)

			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(opts).ToNot(BeNil())
				g.Expect(opts.BearerToken).To(BeEmpty())
				g.Expect(opts.Username).To(BeEmpty())
				g.Expect(opts.Password).To(BeEmpty())
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileSource_checkoutStrategy(t *testing.T) {
	g := NewWithT(t)

	branches := []string{"staging"}
	tags := []string{"non-semver-tag", "v0.1.0", "0.2.0", "v0.2.1", "v1.0.0-alpha", "v1.1.0", "v2.0.0"}
	refs := []string{"refs/pull/420/head"}

	tests := []struct {
		name                 string
		reference            *sourcev1.GitRepositoryRef
		beforeFunc           func(obj *sourcev1.GitRepository, latestRev string)
		want                 sreconcile.Result
		wantErr              bool
		wantRevision         string
		wantArtifactOutdated bool
		wantReconciling      bool
	}{
		{
			name:            "Nil reference (default branch)",
			want:            sreconcile.ResultSuccess,
			wantRevision:    "master@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "Branch",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "staging@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "Tag",
			reference: &sourcev1.GitRepositoryRef{
				Tag: "v0.1.0",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "v0.1.0@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "Branch commit",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
				Commit: "<commit>",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "staging@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "Ref Name pointing to a branch",
			reference: &sourcev1.GitRepositoryRef{
				Name: "refs/heads/staging",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "refs/heads/staging@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "Ref Name pointing to a PR",
			reference: &sourcev1.GitRepositoryRef{
				Name: "refs/pull/420/head",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "refs/pull/420/head@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "SemVer",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "*",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "v2.0.0@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "SemVer range",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: "<v0.2.1",
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "0.2.0@sha1:<commit>",
			wantReconciling: true,
		},
		{
			name: "SemVer prerelease",
			reference: &sourcev1.GitRepositoryRef{
				SemVer: ">=1.0.0-0 <1.1.0-0",
			},
			wantRevision:    "v1.0.0-alpha@sha1:<commit>",
			want:            sreconcile.ResultSuccess,
			wantReconciling: true,
		},
		{
			name: "Existing artifact makes ArtifactOutdated=True",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			beforeFunc: func(obj *sourcev1.GitRepository, latestRev string) {
				obj.Status = sourcev1.GitRepositoryStatus{
					Artifact: &meta.Artifact{
						Revision: "staging/some-revision",
						Path:     randStringRunes(10),
					},
				}
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "foo")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			want:                 sreconcile.ResultSuccess,
			wantRevision:         "staging@sha1:<commit>",
			wantArtifactOutdated: true,
			wantReconciling:      true,
		},
		{
			name: "Optimized clone",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			beforeFunc: func(obj *sourcev1.GitRepository, latestRev string) {
				// Add existing artifact on the object and storage.
				obj.Status = sourcev1.GitRepositoryStatus{
					Artifact: &meta.Artifact{
						Revision: "staging@sha1:" + latestRev,
						Path:     randStringRunes(10),
					},
				}
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "foo")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			want:            sreconcile.ResultEmpty,
			wantErr:         true,
			wantRevision:    "staging@sha1:<commit>",
			wantReconciling: false,
		},
		{
			name: "Optimized clone different ignore",
			reference: &sourcev1.GitRepositoryRef{
				Branch: "staging",
			},
			beforeFunc: func(obj *sourcev1.GitRepository, latestRev string) {
				// Set new ignore value.
				obj.Spec.Ignore = ptr.To("foo")
				// Add existing artifact on the object and storage.
				obj.Status = sourcev1.GitRepositoryStatus{
					Artifact: &meta.Artifact{
						Revision: "staging@sha1:" + latestRev,
						Path:     randStringRunes(10),
					},
				}
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "foo")
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "foo")
			},
			want:            sreconcile.ResultSuccess,
			wantRevision:    "staging@sha1:<commit>",
			wantReconciling: false,
		},
	}

	server, err := gittestserver.NewTempGitServer()
	g.Expect(err).To(BeNil())
	defer os.RemoveAll(server.Root())
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

	for _, ref := range refs {
		g.Expect(remoteRefForHead(localRepo, headRef, ref)).To(Succeed())
	}

	r := &GitRepositoryReconciler{
		Client: fakeclient.NewClientBuilder().
			WithScheme(testEnv.GetScheme()).
			WithStatusSubresource(&sourcev1.GitRepository{}).
			Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
					Generation:   1,
				},
				Spec: sourcev1.GitRepositorySpec{
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: timeout},
					URL:       server.HTTPAddress() + repoPath,
					Reference: tt.reference,
				},
			}

			if obj.Spec.Reference != nil && obj.Spec.Reference.Commit == "<commit>" {
				obj.Spec.Reference.Commit = headRef.Hash().String()
			}

			tmpDir := t.TempDir()

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, headRef.Hash().String())
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			var commit git.Commit
			var includes artifactSet
			sp := patch.NewSerialPatcher(obj, r.Client)
			got, err := r.reconcileSource(ctx, sp, obj, &commit, &includes, tmpDir)
			if err != nil && !tt.wantErr {
				t.Log(err)
			}
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			if tt.wantRevision != "" && !tt.wantErr {
				revision := strings.ReplaceAll(tt.wantRevision, "<commit>", headRef.Hash().String())
				g.Expect(commitReference(obj, &commit)).To(Equal(revision))
				g.Expect(conditions.IsTrue(obj, sourcev1.ArtifactOutdatedCondition)).To(Equal(tt.wantArtifactOutdated))
				g.Expect(conditions.IsTrue(obj, meta.ReconcilingCondition)).To(Equal(tt.wantReconciling))
			}
			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestGitRepositoryReconciler_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		dir              string
		includes         artifactSet
		beforeFunc       func(obj *sourcev1.GitRepository)
		afterFunc        func(t *WithT, obj *sourcev1.GitRepository)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Archiving artifact to storage makes ArtifactInStorage=True",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name:     "Archiving artifact to storage with includes makes ArtifactInStorage=True",
			dir:      "testdata/git/repository",
			includes: artifactSet{&meta.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"}},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Include = []sourcev1.GitRepositoryInclude{
					{GitRepositoryRef: meta.LocalObjectReference{Name: "foo"}},
				}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:34d9af1a2fcfaef3ee9487d67dc2d642bc7babdb9444a5f60d1f32df32e4de7d"))
				t.Expect(obj.Status.IncludedArtifacts).ToNot(BeEmpty())
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name:     "Up-to-date artifact should not update status",
			dir:      "testdata/git/repository",
			includes: artifactSet{&meta.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91", Digest: "some-checksum"}},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Include = []sourcev1.GitRepositoryInclude{
					{GitRepositoryRef: meta.LocalObjectReference{Name: "foo"}},
				}
				obj.Status.Artifact = &meta.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"}
				obj.Status.IncludedArtifacts = []*meta.Artifact{{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91", Digest: "some-checksum"}}
				obj.Status.ObservedInclude = obj.Spec.Include
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name: "Spec ignore overwrite is taken into account",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Ignore = ptr.To("!**.txt\n")
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:a17037f96f541a47bdadcd12ab40b943c50a9ffd25dc8a30a5e9af52971fd94f"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name: "Source ignore for subdir ignore patterns",
			dir:  "testdata/git/repowithsubdirs",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:ad9943d761b30e943e2a770ea9083a40fc03f09846efd61f6c442cc48fefad11"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name: "Removes ArtifactOutdatedCondition after creating new artifact",
			dir:  "testdata/git/repository",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:34d9af1a2fcfaef3ee9487d67dc2d642bc7babdb9444a5f60d1f32df32e4de7d"))
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision 'main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'"),
			},
		},
		{
			name:    "Target path does not exists",
			dir:     "testdata/git/foo",
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.StatOperationFailedReason, "failed to stat target artifact path"),
			},
		},
		{
			name:    "Target path is not a directory",
			dir:     "testdata/git/repository/foo.txt",
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.InvalidPathReason, "invalid target path"),
			},
		},
	}
	artifactSize := func(g *WithT, artifactURL string) *int64 {
		if artifactURL == "" {
			return nil
		}
		res, err := http.Get(artifactURL)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(res.StatusCode).To(Equal(http.StatusOK))
		defer res.Body.Close()
		return &res.ContentLength
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			resetChmod(tt.dir, 0o750, 0o600)

			r := &GitRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
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

			commit := git.Commit{
				Hash:      []byte("b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"),
				Reference: "refs/heads/main",
			}
			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileArtifact(ctx, sp, obj, &commit, &tt.includes, tt.dir)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			if obj.Status.Artifact != nil {
				g.Expect(obj.Status.Artifact.Size).To(Equal(artifactSize(g, obj.Status.Artifact.URL)))
			}

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileInclude(t *testing.T) {
	g := NewWithT(t)

	server, err := testserver.NewTempArtifactServer()
	g.Expect(err).NotTo(HaveOccurred())
	server.Start()
	defer server.Stop()
	storage, err := newTestStorage(server.HTTPServer)
	g.Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(storage.BasePath)

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
		want             sreconcile.Result
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
				{name: "a", toPath: "a/", shouldExist: true},
				{name: "b", toPath: "b/", shouldExist: true},
			},
			want: sreconcile.ResultSuccess,
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
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, "CopyFailure", "unpack/path: no such file or directory"),
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
					obj.Status.Artifact = &meta.Artifact{
						Path:           d.name + ".tar.gz",
						Revision:       d.name,
						LastUpdateTime: metav1.Now(),
					}
					g.Expect(storage.Archive(obj.GetArtifact(), "testdata/git/repository", nil)).To(Succeed())
				}
				depObjs = append(depObjs, obj)
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.GitRepository{})

			if len(tt.dependencies) > 0 {
				clientBuilder.WithObjects(depObjs...)
			}

			r := &GitRepositoryReconciler{
				Client:            clientBuilder.Build(),
				EventRecorder:     record.NewFakeRecorder(32),
				Storage:           storage,
				requeueDependency: dependencyInterval,
				features:          features.FeatureGates(),
				patchOptions:      getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
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

			tmpDir := t.TempDir()

			var commit git.Commit
			var includes artifactSet

			// Build includes artifactSet.
			artifactSet, err := r.fetchIncludes(ctx, obj)
			g.Expect(err).ToNot(HaveOccurred())
			includes = *artifactSet

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileInclude(ctx, sp, obj, &commit, &includes, tmpDir)
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if err == nil {
				g.Expect(len(includes)).To(Equal(len(tt.includes)))
			}
			g.Expect(got).To(Equal(tt.want))
			for _, i := range tt.includes {
				if i.toPath != "" {
					expect := g.Expect(filepath.Join(tmpDir, i.toPath))
					if i.shouldExist {
						expect.To(BeADirectory())
					} else {
						expect.NotTo(BeADirectory())
					}
				}
				if i.shouldExist {
					g.Expect(filepath.Join(tmpDir, i.toPath)).Should(BeADirectory())
				} else {
					g.Expect(filepath.Join(tmpDir, i.toPath)).ShouldNot(BeADirectory())
				}
			}
		})
	}
}

func TestGitRepositoryReconciler_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.GitRepository, storage *storage.Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *meta.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *storage.Storage) error {
				revisions := []string{"a", "b", "c", "d"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &meta.Artifact{
						Path:     fmt.Sprintf("/reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}
					if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0o640); err != nil {
						return err
					}
					if n != len(revisions)-1 {
						time.Sleep(time.Second * 1)
					}
				}
				storage.SetArtifactURL(obj.Status.Artifact)
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			assertArtifact: &meta.Artifact{
				Path:     "/reconcile-storage/d.txt",
				Revision: "d",
				Digest:   "sha256:18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
				URL:      testStorage.Hostname + "/reconcile-storage/d.txt",
				Size:     int64p(int64(len("d"))),
			},
			assertPaths: []string{
				"/reconcile-storage/d.txt",
				"/reconcile-storage/c.txt",
				"!/reconcile-storage/b.txt",
				"!/reconcile-storage/a.txt",
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "build artifact first time",
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact"),
			},
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/reconcile-storage/invalid.txt",
					Revision: "e",
				}
				storage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices empty artifact digest",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *storage.Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = ""

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/empty-digest.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices artifact digest mismatch",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *storage.Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = "sha256:6c329d5322473f904e2f908a51c12efa0ca8aa4201dd84f2c9d203a6ab3e9023"

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/reconcile-storage/digest-mismatch.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/reconcile-storage/hostname.txt",
					Revision: "f",
					Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
					URL:      "http://outdated.com/reconcile-storage/hostname.txt",
				}
				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0o640); err != nil {
					return err
				}
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"/reconcile-storage/hostname.txt",
			},
			assertArtifact: &meta.Artifact{
				Path:     "/reconcile-storage/hostname.txt",
				Revision: "f",
				Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
				URL:      testStorage.Hostname + "/reconcile-storage/hostname.txt",
				Size:     int64p(int64(len("file"))),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			defer func() {
				g.Expect(os.RemoveAll(filepath.Join(testStorage.BasePath, "/reconcile-storage"))).To(Succeed())
			}()

			r := &GitRepositoryReconciler{
				Client: fakeclient.NewClientBuilder().
					WithScheme(testEnv.GetScheme()).
					WithStatusSubresource(&sourcev1.GitRepository{}).
					Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   1,
				},
			}
			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			g.Expect(r.Client.Create(context.TODO(), obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(context.TODO(), obj)).ToNot(HaveOccurred())
			}()

			var c *git.Commit
			var as artifactSet
			sp := patch.NewSerialPatcher(obj, r.Client)
			got, err := r.reconcileStorage(context.TODO(), sp, obj, c, &as, "")
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))

			g.Expect(obj.Status.Artifact).To(MatchArtifact(tt.assertArtifact))
			if tt.assertArtifact != nil && tt.assertArtifact.URL != "" {
				g.Expect(obj.Status.Artifact.URL).To(Equal(tt.assertArtifact.URL))
			}
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			for _, p := range tt.assertPaths {
				absoluteP := filepath.Join(testStorage.BasePath, p)
				if !strings.HasPrefix(p, "!") {
					g.Expect(absoluteP).To(BeAnExistingFile())
					continue
				}
				g.Expect(absoluteP).NotTo(BeAnExistingFile())
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestGitRepositoryReconciler_reconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &GitRepositoryReconciler{
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		features:      features.FeatureGates(),
		patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
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
	g.Expect(got).To(Equal(sreconcile.ResultEmpty))
	g.Expect(controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer)).To(BeFalse())
	g.Expect(obj.Status.Artifact).To(BeNil())
}

func TestGitRepositoryReconciler_verifySignature(t *testing.T) {
	tests := []struct {
		name                       string
		secret                     *corev1.Secret
		commit                     git.Commit
		beforeFunc                 func(obj *sourcev1.GitRepository)
		want                       sreconcile.Result
		wantErr                    bool
		err                        error
		wantSourceVerificationMode *sourcev1.GitVerificationMode
		assertConditions           []metav1.Condition
	}{
		{
			name: "Valid commit with mode=HEAD makes SourceVerifiedCondition=True",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(encodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want:                       sreconcile.ResultSuccess,
			wantSourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitHEAD),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of\n\t- commit 'shasum' with key '5982D0279C227FFD'"),
			},
		},
		{
			name: "Valid commit with mode=head makes SourceVerifiedCondition=True",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(encodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: "head",
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want:                       sreconcile.ResultSuccess,
			wantSourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitHEAD),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of\n\t- commit 'shasum' with key '5982D0279C227FFD'"),
			},
		},
		{
			name: "Valid tag with mode=tag makes SourceVerifiedCondition=True",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				ReferencingTag: &git.Tag{
					Name:      "v0.1.0",
					Hash:      []byte("shasum"),
					Encoded:   []byte(encodedTagFixture),
					Signature: signatureTagFixture,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Tag: "v0.1.0",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTag,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want:                       sreconcile.ResultSuccess,
			wantSourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTag),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of\n\t- tag 'v0.1.0@shasum' with key '5982D0279C227FFD'"),
			},
		},
		{
			name: "Valid tag and commit with mode=TagAndHEAD makes SourceVerifiedCondition=True",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(encodedCommitFixture),
				Signature: signatureCommitFixture,
				ReferencingTag: &git.Tag{
					Name:      "v0.1.0",
					Hash:      []byte("shasum"),
					Encoded:   []byte(encodedTagFixture),
					Signature: signatureTagFixture,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Tag: "v0.1.0",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTagAndHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			want:                       sreconcile.ResultSuccess,
			wantSourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTagAndHEAD),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of\n\t- tag 'v0.1.0@shasum' with key '5982D0279C227FFD'\n\t- commit 'shasum' with key '5982D0279C227FFD'"),
			},
		},
		{
			name: "Source verification mode in status is unset if there's no verification in spec",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.SourceVerificationMode = ptrToVerificationMode(sourcev1.ModeGitHEAD)
				obj.Spec.Verification = nil
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name: "Verification of tag with no tag ref SourceVerifiedCondition=False and returns a stalling error",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Branch: "main",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTag,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			err: serror.NewStalling(
				errors.New("cannot verify tag object's signature if a tag reference is not specified"),
				"InvalidVerificationMode",
			),
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidVerificationMode", "cannot verify tag object's signature if a tag reference is not specified"),
			},
		},
		{
			name: "Unsigned tag with mode=tag makes SourceVerifiedCondition=False",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				ReferencingTag: &git.Tag{
					Name:    "v0.1.0",
					Hash:    []byte("shasum"),
					Encoded: []byte(encodedTagFixture),
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Tag: "v0.1.0",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTag,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidGitObject", "cannot verify signature of tag 'v0.1.0@shasum' since it is not signed"),
			},
		},
		{
			name: "Partially successful verification makes SourceVerifiedCondition=False",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(malformedEncodedCommitFixture),
				Signature: signatureCommitFixture,
				ReferencingTag: &git.Tag{
					Name:      "v0.1.0",
					Hash:      []byte("shasum"),
					Encoded:   []byte(encodedTagFixture),
					Signature: signatureTagFixture,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Tag: "v0.1.0",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTagAndHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "signature verification of commit 'shasum' failed: unable to verify Git commit: unable to verify payload with any of the given key rings"),
			},
		},
		{
			name: "Invalid commit makes SourceVerifiedCondition=False and returns error",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(malformedEncodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "signature verification of commit 'shasum' failed: unable to verify Git commit: unable to verify payload with any of the given key rings"),
			},
		},
		{
			name: "Invalid tag signature with mode=tag makes SourceVerifiedCondition=False",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "existing",
				},
				Data: map[string][]byte{
					"foo": []byte(armoredKeyRingFixture),
				},
			},
			commit: git.Commit{
				ReferencingTag: &git.Tag{
					Name:      "v0.1.0",
					Hash:      []byte("shasum"),
					Encoded:   []byte(malformedEncodedTagFixture),
					Signature: signatureTagFixture,
				},
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Reference = &sourcev1.GitRepositoryRef{
					Tag: "v0.1.0",
				}
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitTag,
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidTagSignature", "signature verification of tag 'v0.1.0@shasum' failed: unable to verify Git tag: unable to verify payload with any of the given key rings"),
			},
		},
		{
			name: "Invalid PGP key makes SourceVerifiedCondition=False and returns error",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid",
				},
				Data: map[string][]byte{
					"foo": []byte("invalid PGP public key"),
				},
			},
			commit: git.Commit{
				Hash:      []byte("shasum"),
				Encoded:   []byte(malformedEncodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "invalid",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "signature verification of commit 'shasum' failed: unable to verify Git commit: unable to read armored key ring: openpgp: invalid argument: no armored data found"),
			},
		},
		{
			name: "Secret get failure makes SourceVerifiedCondition=False and returns error",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: sourcev1.ModeGitHEAD,
					SecretRef: meta.LocalObjectReference{
						Name: "none-existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "VerificationError", "PGP public keys secret error: secrets \"none-existing\" not found"),
			},
		},
		{
			name: "Nil verification in spec deletes SourceVerified condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
			},
			want:             sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{},
		},
		{
			name: "Empty verification mode in spec deletes SourceVerified condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
			},
			want:             sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.GitRepository{})

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret)
			}

			r := &GitRepositoryReconciler{
				EventRecorder: record.NewFakeRecorder(32),
				Client:        clientBuilder.Build(),
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
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

			got, err := r.verifySignature(context.TODO(), obj, tt.commit)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if tt.err != nil {
				g.Expect(err).To(Equal(tt.err))
			}
			g.Expect(got).To(Equal(tt.want))
			if tt.wantSourceVerificationMode != nil {
				g.Expect(*obj.Status.SourceVerificationMode).To(Equal(*tt.wantSourceVerificationMode))
			} else {
				g.Expect(obj.Status.SourceVerificationMode).To(BeNil())
			}
		})
	}
}

func TestGitRepositoryReconciler_ConditionsUpdate(t *testing.T) {
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

	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.GitRepository)
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "no failure condition",
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
		{
			name: "reconciling condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, meta.ReconcilingCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
		{
			name: "stalled condition",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, meta.StalledCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
		{
			name: "mixed failed conditions",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "Foo", "")
				conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "Foo", "")
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Foo", "")
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
		{
			name: "reconciling and failed conditions",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, meta.ReconcilingCondition, "Foo", "")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
		{
			name: "stalled and failed conditions",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, meta.StalledCondition, "Foo", "")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "Foo", "")
			},
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "Succeeded", "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, "Succeeded", "stored artifact for revision"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "condition-update",
					Namespace:  "default",
					Finalizers: []string{sourcev1.SourceFinalizer},
				},
				Spec: sourcev1.GitRepositorySpec{
					URL:      server.HTTPAddress() + repoPath,
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithObjects(obj).
				WithStatusSubresource(&sourcev1.GitRepository{})

			r := &GitRepositoryReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}

			key := client.ObjectKeyFromObject(obj)
			res, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: key})
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(res).To(Equal(tt.want))

			updatedObj := &sourcev1.GitRepository{}
			err = r.Get(ctx, key, updatedObj)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(updatedObj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
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

func remoteRefForHead(repo *gogit.Repository, head *plumbing.Reference, reference string) error {
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(reference), head.Hash())); err != nil {
		return err
	}
	if err := repo.Push(&gogit.PushOptions{
		RefSpecs: []config.RefSpec{
			config.RefSpec("+" + reference + ":" + reference),
		},
	}); err != nil {
		return err
	}
	return nil
}

func TestGitRepositoryReconciler_statusConditions(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.GitRepository)
		assertConditions []metav1.Condition
		wantErr          bool
	}{
		{
			name: "multiple positive conditions",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of commit")
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of commit"),
			},
		},
		{
			name: "multiple failures",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
				conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "IllegalPath", "some error")
				conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory")
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "IllegalPath", "some error"),
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.DirCreationFailedReason, "failed to create directory"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "some error"),
			},
			wantErr: true,
		},
		{
			name: "mixed positive and negative conditions",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision")
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret")
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get secret"),
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for revision"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.GitRepository{
				TypeMeta: metav1.TypeMeta{
					APIVersion: sourcev1.GroupVersion.String(),
					Kind:       sourcev1.GitRepositoryKind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gitrepo",
					Namespace: "foo",
				},
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.Scheme()).
				WithObjects(obj).
				WithStatusSubresource(&sourcev1.GitRepository{})

			c := clientBuilder.Build()

			serialPatcher := patch.NewSerialPatcher(obj, c)

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			ctx := context.TODO()
			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), serialPatcher)
			summarizeOpts := []summarize.Option{
				summarize.WithConditions(gitRepositoryReadyCondition),
				summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
				summarize.WithReconcileResult(sreconcile.ResultSuccess),
				summarize.WithIgnoreNotFound(),
				summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
					RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
				}),
				summarize.WithPatchFieldOwner("source-controller"),
			}
			_, err := summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)
			g.Expect(err != nil).To(Equal(tt.wantErr))

			key := client.ObjectKeyFromObject(obj)
			g.Expect(c.Get(ctx, key, obj)).ToNot(HaveOccurred())
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestGitRepositoryReconciler_notify(t *testing.T) {
	concreteCommit := git.Commit{
		Hash:    git.Hash("b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"),
		Message: "test commit",
		Encoded: []byte("content"),
	}
	partialCommit := git.Commit{
		Hash: git.Hash("b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"),
	}

	noopErr := serror.NewGeneric(fmt.Errorf("some no-op error"), "NoOpReason")
	noopErr.Ignore = true

	tests := []struct {
		name             string
		res              sreconcile.Result
		resErr           error
		oldObjBeforeFunc func(obj *sourcev1.GitRepository)
		newObjBeforeFunc func(obj *sourcev1.GitRepository)
		commit           git.Commit
		wantEvent        string
	}{
		{
			name:   "error - no event",
			res:    sreconcile.ResultEmpty,
			resErr: errors.New("some error"),
		},
		{
			name:   "new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
			},
			commit:    concreteCommit,
			wantEvent: "Normal NewArtifact stored artifact for commit 'test commit'",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			commit:    concreteCommit,
			wantEvent: "Normal Succeeded stored artifact for commit 'test commit'",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			commit:    concreteCommit,
			wantEvent: "Normal NewArtifact stored artifact for commit 'test commit'",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
		{
			name:   "no-op error result",
			res:    sreconcile.ResultEmpty,
			resErr: noopErr,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			commit:    partialCommit, // no-op will always result in partial commit.
			wantEvent: "Normal Succeeded stored artifact for commit 'sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.GitRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &GitRepositoryReconciler{
				EventRecorder: recorder,
				features:      features.FeatureGates(),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
			}
			reconciler.notify(ctx, oldObj, newObj, tt.commit, tt.res, tt.resErr)

			select {
			case x, ok := <-recorder.Events:
				g.Expect(ok).To(Equal(tt.wantEvent != ""), "unexpected event received")
				if tt.wantEvent != "" {
					g.Expect(x).To(ContainSubstring(tt.wantEvent))
				}
			default:
				if tt.wantEvent != "" {
					t.Errorf("expected some event to be emitted")
				}
			}
		})
	}
}

func TestGitRepositoryReconciler_fetchIncludes(t *testing.T) {
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
		wantErr          bool
		wantArtifactSet  artifactSet
		assertConditions []metav1.Condition
	}{
		{
			name: "Existing includes",
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
				{name: "a", toPath: "a/", shouldExist: true},
				{name: "b", toPath: "b/", shouldExist: true},
			},
			wantErr: false,
			wantArtifactSet: []*meta.Artifact{
				{Revision: "a"},
				{Revision: "b"},
			},
		},
		{
			name: "Include get failure",
			includes: []include{
				{name: "a", toPath: "a/"},
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "NotFound", "could not get resource for include 'a': gitrepositories.source.werf.io \"a\" not found"),
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
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "NoArtifact", "no artifact available for include 'a'"),
			},
		},
		{
			name: "Outdated IncludeUnavailable is removed",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NoArtifact", "")
			},
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
					obj.Status.Artifact = &meta.Artifact{
						Path:           d.name + ".tar.gz",
						Revision:       d.name,
						LastUpdateTime: metav1.Now(),
					}
				}
				depObjs = append(depObjs, obj)
			}

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.GitRepository{})

			if len(tt.dependencies) > 0 {
				clientBuilder.WithObjects(depObjs...)
			}

			r := &GitRepositoryReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				patchOptions:  getPatchOptions(gitRepositoryReadyCondition.Owned, "sc"),
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

			gotArtifactSet, err := r.fetchIncludes(ctx, obj)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(obj.GetConditions()).To(conditions.MatchConditions(tt.assertConditions))
			if !tt.wantErr && gotArtifactSet != nil {
				g.Expect(gotArtifactSet.Diff(tt.wantArtifactSet)).To(BeFalse())
			}
		})
	}
}

func resetChmod(path string, dirMode os.FileMode, fileMode os.FileMode) error {
	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() && info.Mode() != dirMode {
				os.Chmod(path, dirMode)
			} else if !info.IsDir() && info.Mode() != fileMode {
				os.Chmod(path, fileMode)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("cannot reset file permissions: %v", err)
	}

	return nil
}

func TestGitRepositoryIncludeEqual(t *testing.T) {
	tests := []struct {
		name string
		a    sourcev1.GitRepositoryInclude
		b    sourcev1.GitRepositoryInclude
		want bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name: "different refs",
			a: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
			},
			b: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "bar"},
			},
			want: false,
		},
		{
			name: "same refs",
			a: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
			},
			b: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
			},
			want: true,
		},
		{
			name: "different from paths",
			a:    sourcev1.GitRepositoryInclude{FromPath: "foo"},
			b:    sourcev1.GitRepositoryInclude{FromPath: "bar"},
			want: false,
		},
		{
			name: "same from paths",
			a:    sourcev1.GitRepositoryInclude{FromPath: "foo"},
			b:    sourcev1.GitRepositoryInclude{FromPath: "foo"},
			want: true,
		},
		{
			name: "different to paths",
			a:    sourcev1.GitRepositoryInclude{ToPath: "foo"},
			b:    sourcev1.GitRepositoryInclude{ToPath: "bar"},
			want: false,
		},
		{
			name: "same to paths",
			a:    sourcev1.GitRepositoryInclude{ToPath: "foo"},
			b:    sourcev1.GitRepositoryInclude{ToPath: "foo"},
			want: true,
		},
		{
			name: "same all",
			a: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "foo-ref"},
				FromPath:         "foo-path",
				ToPath:           "bar-path",
			},
			b: sourcev1.GitRepositoryInclude{
				GitRepositoryRef: meta.LocalObjectReference{Name: "foo-ref"},
				FromPath:         "foo-path",
				ToPath:           "bar-path",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(gitRepositoryIncludeEqual(tt.a, tt.b)).To(Equal(tt.want))
		})
	}
}

func TestGitContentConfigChanged(t *testing.T) {
	tests := []struct {
		name      string
		obj       sourcev1.GitRepository
		artifacts []*meta.Artifact
		want      bool
	}{
		{
			name: "no content config",
			want: false,
		},
		{
			name: "unobserved ignore",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{Ignore: ptr.To("foo")},
			},
			want: true,
		},
		{
			name: "observed ignore",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{Ignore: ptr.To("foo")},
				Status: sourcev1.GitRepositoryStatus{ObservedIgnore: ptr.To("foo")},
			},
			want: false,
		},
		{
			name: "unobserved recurse submodules",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{RecurseSubmodules: true},
			},
			want: true,
		},
		{
			name: "observed recurse submodules",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{RecurseSubmodules: true},
				Status: sourcev1.GitRepositoryStatus{ObservedRecurseSubmodules: true},
			},
			want: false,
		},
		{
			name: "unobserved sparse checkout",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{SparseCheckout: []string{"a/b/c", "x/y/z"}},
				Status: sourcev1.GitRepositoryStatus{ObservedSparseCheckout: []string{"a/b/c"}},
			},
			want: true,
		},
		{
			name: "unobserved case sensitive sparse checkout",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{SparseCheckout: []string{"a/b/c", "x/y/Z"}},
				Status: sourcev1.GitRepositoryStatus{ObservedSparseCheckout: []string{"a/b/c", "x/y/z"}},
			},
			want: true,
		},
		{
			name: "observed sparse checkout",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{SparseCheckout: []string{"a/b/c", "x/y/z"}},
				Status: sourcev1.GitRepositoryStatus{ObservedSparseCheckout: []string{"a/b/c", "x/y/z"}},
			},
			want: false,
		},
		{
			name: "observed sparse checkout with leading slash",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{SparseCheckout: []string{"./a/b/c", "./x/y/z"}},
				Status: sourcev1.GitRepositoryStatus{ObservedSparseCheckout: []string{"./a/b/c", "./x/y/z"}},
			},
			want: false,
		},
		{
			name: "unobserved include",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{GitRepositoryRef: meta.LocalObjectReference{Name: "foo"}, FromPath: "bar", ToPath: "baz"},
					},
				},
			},
			want: true,
		},
		{
			name: "observed include",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "bbb"},
			},
			want: false,
		},
		{
			name: "observed include but different artifact revision",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "ccc", Digest: "bbb"},
			},
			want: true,
		},
		{
			name: "observed include but different artifact digest",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "ddd"},
			},
			want: true,
		},
		{
			name: "observed include but updated spec",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "bbb"},
			},
			want: true,
		},
		{
			name: "different number of include and observed include",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					IncludedArtifacts: []*meta.Artifact{
						{Revision: "aaa", Digest: "bbb"},
						{Revision: "ccc", Digest: "ccc"},
					},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "bbb"},
				{Revision: "ccc", Digest: "ddd"},
			},
			want: true,
		},
		{
			name: "different number of include and artifactset",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{
						{Revision: "aaa", Digest: "bbb"},
						{Revision: "ccc", Digest: "ccc"},
					},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "bbb"},
			},
			want: true,
		},
		{
			name: "different number of include and included artifacts",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Include: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					ObservedInclude: []sourcev1.GitRepositoryInclude{
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
						{
							GitRepositoryRef: meta.LocalObjectReference{Name: "foo2"},
							FromPath:         "bar",
							ToPath:           "baz",
						},
					},
					IncludedArtifacts: []*meta.Artifact{
						{Revision: "aaa", Digest: "bbb"},
					},
				},
			},
			artifacts: []*meta.Artifact{
				{Revision: "aaa", Digest: "bbb"},
				{Revision: "ccc", Digest: "ccc"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			includes := artifactSet(tt.artifacts)
			g.Expect(gitContentConfigChanged(&tt.obj, &includes)).To(Equal(tt.want))
		})
	}
}

func Test_requiresVerification(t *testing.T) {
	tests := []struct {
		name string
		obj  *sourcev1.GitRepository
		want bool
	}{
		{
			name: "GitRepository without verification does not require verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{},
			},
			want: false,
		},
		{
			name: "GitRepository with verification and no observed verification mode in status requires verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{},
				},
			},
			want: true,
		},
		{
			name: "GitRepository with HEAD verification and a verified tag requires verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitHEAD,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTag),
				},
			},
			want: true,
		},
		{
			name: "GitRepository with tag and HEAD verification and a verified tag requires verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitTagAndHEAD,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTag),
				},
			},
			want: true,
		},
		{
			name: "GitRepository with tag verification and a verified HEAD requires verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitTag,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitHEAD),
				},
			},
			want: true,
		},
		{
			name: "GitRepository with tag and HEAD verification and a verified HEAD requires verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitTagAndHEAD,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitHEAD),
				},
			},
			want: true,
		},
		{
			name: "GitRepository with tag verification and a verified HEAD and tag does not require verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitTag,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTagAndHEAD),
				},
			},
			want: false,
		},
		{
			name: "GitRepository with head verification and a verified HEAD and tag does not require verification",
			obj: &sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{
					Verification: &sourcev1.GitRepositoryVerification{
						Mode: sourcev1.ModeGitHEAD,
					},
				},
				Status: sourcev1.GitRepositoryStatus{
					SourceVerificationMode: ptrToVerificationMode(sourcev1.ModeGitTagAndHEAD),
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			verificationRequired := requiresVerification(tt.obj)
			g.Expect(verificationRequired).To(Equal(tt.want))
		})
	}
}

func ptrToVerificationMode(mode sourcev1.GitVerificationMode) *sourcev1.GitVerificationMode {
	return &mode
}
