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
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	. "github.com/onsi/gomega"
	sshtestdata "golang.org/x/crypto/ssh/testdata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/gittestserver"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/ssh"
	"github.com/fluxcd/pkg/testserver"

	"github.com/fluxcd/pkg/git"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/features"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
)

const (
	encodedCommitFixture = `tree f0c522d8cc4c90b73e2bc719305a896e7e3c108a
parent eb167bc68d0a11530923b1f24b4978535d10b879
author Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300
committer Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300

Update containerd and runc to fix CVEs

Signed-off-by: Stefan Prodan <stefan.prodan@gmail.com>
`
	malformedEncodedCommitFixture = `parent eb167bc68d0a11530923b1f24b4978535d10b879
author Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300
committer Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300

Update containerd and runc to fix CVEs

Signed-off-by: Stefan Prodan <stefan.prodan@gmail.com>
`
	signatureCommitFixture = `-----BEGIN PGP SIGNATURE-----

iHUEABEIAB0WIQQHgExUr4FrLdKzpNYyma6w5AhbrwUCYV//1AAKCRAyma6w5Ahb
r7nJAQCQU4zEJu04/Q0ac/UaL6htjhq/wTDNMeUM+aWG/LcBogEAqFUea1oR2BJQ
JCJmEtERFh39zNWSazQmxPAFhEE0kbc=
=+Wlj
-----END PGP SIGNATURE-----`
	armoredKeyRingFixture = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQSuBF9+HgMRDADKT8UBcSzpTi4JXt/ohhVW3x81AGFPrQvs6MYrcnNJfIkPTJD8
mY5T7j1fkaN5wcf1wnxM9qTcW8BodkWNGEoEYOtVuigLSxPFqIncxK0PHvdU8ths
TEInBrgZv9t6xIVa4QngOEUd2D/aYni7M+75z7ntgj6eU1xLZ60upRFn05862OvJ
rZFUvzjsZXMAO3enCu2VhG/2axCY/5uI8PgWjyiKV2TH4LBJgzlb0v6SyI+fYf5K
Bg2WzDuLKvQBi9tFSwnUbQoFFlOeiGW8G/bdkoJDWeS1oYgSD3nkmvXvrVESCrbT
C05OtQOiDXjSpkLim81vNVPtI2XEug+9fEA+jeJakyGwwB+K8xqV3QILKCoWHKGx
yWcMHSR6cP9tdXCk2JHZBm1PLSJ8hIgMH/YwBJLYg90u8lLAs9WtpVBKkLplzzgm
B4Z4VxCC+xI1kt+3ZgYvYC+oUXJXrjyAzy+J1f+aWl2+S/79glWgl/xz2VibWMz6
nZUE+wLMxOQqyOsBALsoE6z81y/7gfn4R/BziBASi1jq/r/wdboFYowmqd39DACX
+i+V0OplP2TN/F5JajzRgkrlq5cwZHinnw+IFwj9RTfOkdGb3YwhBt/h2PP38969
ZG+y8muNtaIqih1pXj1fz9HRtsiCABN0j+JYpvV2D2xuLL7P1O0dt5BpJ3KqNCRw
mGgO2GLxbwvlulsLidCPxdK/M8g9Eeb/xwA5LVwvjVchHkzHuUT7durn7AT0RWiK
BT8iDfeBB9RKienAbWyybEqRaR6/Tv+mghFIalsDiBPbfm4rsNzsq3ohfByqECiy
yUvs2O3NDwkoaBDkA3GFyKv8/SVpcuL5OkVxAHNCIMhNzSgotQ3KLcQc0IREfFCa
3CsBAC7CsE2bJZ9IA9sbBa3jimVhWUQVudRWiLFeYHUF/hjhqS8IHyFwprjEOLaV
EG0kBO6ELypD/bOsmN9XZLPYyI3y9DM6Vo0KMomE+yK/By/ZMxVfex8/TZreUdhP
VdCLL95Rc4w9io8qFb2qGtYBij2wm0RWLcM0IhXWAtjI3B17IN+6hmv+JpiZccsM
AMNR5/RVdXIl0hzr8LROD0Xe4sTyZ+fm3mvpczoDPQNRrWpmI/9OT58itnVmZ5jM
7djV5y/NjBk63mlqYYfkfWto97wkhg0MnTnOhzdtzSiZQRzj+vf+ilLfIlLnuRr1
JRV9Skv6xQltcFArx4JyfZCo7JB1ZXcbdFAvIXXS11RTErO0XVrXNm2RenpW/yZA
9f+ESQ/uUB6XNuyqVUnJDAFJFLdzx8sO3DXo7dhIlgpFqgQobUl+APpbU5LT95sm
89UrV0Lt9vh7k6zQtKOjEUhm+dErmuBnJo8MvchAuXLagHjvb58vYBCUxVxzt1KG
2IePwJ/oXIfawNEGad9Lmdo1FYG1u53AKWZmpYOTouu92O50FG2+7dBh0V2vO253
aIGFRT1r14B1pkCIun7z7B/JELqOkmwmlRrUnxlADZEcQT3z/S8/4+2P7P6kXO7X
/TAX5xBhSqUbKe3DhJSOvf05/RVL5ULc2U2JFGLAtmBOFmnD/u0qoo5UvWliI+v/
47QnU3RlZmFuIFByb2RhbiA8c3RlZmFuLnByb2RhbkBnbWFpbC5jb20+iJAEExEI
ADgWIQQHgExUr4FrLdKzpNYyma6w5AhbrwUCX34eAwIbAwULCQgHAgYVCgkICwIE
FgIDAQIeAQIXgAAKCRAyma6w5Ahbrzu/AP9l2YpRaWZr6wSQuEn0gMN8DRzsWJPx
pn0akdY7SRP3ngD9GoKgu41FAItnHAJ2KiHv/fHFyHMndNP3kPGPNW4BF+65Aw0E
X34eAxAMAMdYFCHmVA8TZxSTMBDpKYave8RiDCMMMjk26Gl0EPN9f2Y+s5++DhiQ
hojNH9VmJkFwZX1xppxe1y1aLa/U6fBAqMP/IdNH8270iv+A9YIxdsWLmpm99BDO
3suRfsHcOe9T0x/CwRfDNdGM/enGMhYGTgF4VD58DRDE6WntaBhl4JJa300NG6X0
GM4Gh59DKWDnez/Shulj8demlWmakP5imCVoY+omOEc2k3nH02U+foqaGG5WxZZ+
GwEPswm2sBxvn8nwjy9gbQwEtzNI7lWYiz36wCj2VS56Udqt+0eNg8WzocUT0XyI
moe1qm8YJQ6fxIzaC431DYi/mCDzgx4EV9ww33SXX3Yp2NL6PsdWJWw2QnoqSMpM
z5otw2KlMgUHkkXEKs0apmK4Hu2b6KD7/ydoQRFUqR38Gb0IZL1tOL6PnbCRUcig
Aypy016W/WMCjBfQ8qxIGTaj5agX2t28hbiURbxZkCkz+Z3OWkO0Rq3Y2hNAYM5s
eTn94JIGGwADBgv/dbSZ9LrBvdMwg8pAtdlLtQdjPiT1i9w5NZuQd7OuKhOxYTEB
NRDTgy4/DgeNThCeOkMB/UQQPtJ3Et45S2YRtnnuvfxgnlz7xlUn765/grtnRk4t
ONjMmb6tZos1FjIJecB/6h4RsvUd2egvtlpD/Z3YKr6MpNjWg4ji7m27e9pcJfP6
YpTDrq9GamiHy9FS2F2pZlQxriPpVhjCLVn9tFGBIsXNxxn7SP4so6rJBmyHEAlq
iym9wl933e0FIgAw5C1vvprYu2amk+jmVBsJjjCmInW5q/kWAFnFaHBvk+v+/7tX
hywWUI7BqseikgUlkgJ6eU7E9z1DEyuS08x/cViDoNh2ntVUhpnluDu48pdqBvvY
a4uL/D+KI84THUAJ/vZy+q6G3BEb4hI9pFjgrdJpUKubxyZolmkCFZHjV34uOcTc
LQr28P8xW8vQbg5DpIsivxYLqDGXt3OyiItxvLMtw/ypt6PkoeP9A4KDST4StITE
1hrOrPtJ/VRmS2o0iHgEGBEIACAWIQQHgExUr4FrLdKzpNYyma6w5AhbrwUCX34e
AwIbDAAKCRAyma6w5Ahbr6QWAP9/pl2R6r1nuCnXzewSbnH1OLsXf32hFQAjaQ5o
Oomb3gD/TRf/nAdVED+k81GdLzciYdUGtI71/qI47G0nMBluLRE=
=/4e+
-----END PGP PUBLIC KEY BLOCK-----
`
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
					Artifact: &sourcev1.Artifact{
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
					Artifact: &sourcev1.Artifact{
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
					Artifact: &sourcev1.Artifact{
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
				obj.Spec.Ignore = pointer.StringPtr("foo")
				// Add existing artifact on the object and storage.
				obj.Status = sourcev1.GitRepositoryStatus{
					Artifact: &sourcev1.Artifact{
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
			includes: artifactSet{&sourcev1.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"}},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Include = []sourcev1.GitRepositoryInclude{
					{GitRepositoryRef: meta.LocalObjectReference{Name: "foo"}},
				}
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:60a3bf69f337cb5ec9ebd00abefbb6e7f2a2cf27158ecf438d52b2035b184172"))
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
			includes: artifactSet{&sourcev1.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91", Digest: "some-checksum"}},
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Include = []sourcev1.GitRepositoryInclude{
					{GitRepositoryRef: meta.LocalObjectReference{Name: "foo"}},
				}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91"}
				obj.Status.IncludedArtifacts = []*sourcev1.Artifact{{Revision: "main@sha1:b9b3feadba509cb9b22e968a5d27e96c2bc2ff91", Digest: "some-checksum"}}
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
				obj.Spec.Ignore = pointer.StringPtr("!**.txt\n")
			},
			afterFunc: func(t *WithT, obj *sourcev1.GitRepository) {
				t.Expect(obj.GetArtifact()).ToNot(BeNil())
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:11f7f007dce5619bd79e6c57688261058d09f5271e802463ac39f2b9ead7cabd"))
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
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:29186e024dde5a414cfc990829c6b2e85f6b3bd2d950f50ca9f418f5d2261d79"))
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
				t.Expect(obj.GetArtifact().Digest).To(Equal("sha256:60a3bf69f337cb5ec9ebd00abefbb6e7f2a2cf27158ecf438d52b2035b184172"))
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

			resetChmod(tt.dir, 0o755, 0o644)

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
					obj.Status.Artifact = &sourcev1.Artifact{
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
		beforeFunc       func(obj *sourcev1.GitRepository, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertConditions []metav1.Condition
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.GitRepository, storage *Storage) error {
				revisions := []string{"a", "b", "c", "d"}
				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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
			beforeFunc: func(obj *sourcev1.GitRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *sourcev1.GitRepository, storage *Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *sourcev1.GitRepository, storage *Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *sourcev1.GitRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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

func TestGitRepositoryReconciler_verifyCommitSignature(t *testing.T) {
	tests := []struct {
		name             string
		secret           *corev1.Secret
		commit           git.Commit
		beforeFunc       func(obj *sourcev1.GitRepository)
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "Valid commit makes SourceVerifiedCondition=True",
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
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of commit 'shasum' with key '3299AEB0E4085BAF'"),
			},
		},
		{
			name: "Invalid commit sets no SourceVerifiedCondition and returns error",
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
					Mode: "head",
					SecretRef: meta.LocalObjectReference{
						Name: "existing",
					},
				}
			},
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "signature verification of commit 'shasum' failed: unable to verify commit with any of the given key rings"),
			},
		},
		{
			name: "Secret get failure sets no SourceVerifiedCondition and returns error",
			beforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Spec.Interval = metav1.Duration{Duration: interval}
				obj.Spec.Verification = &sourcev1.GitRepositoryVerification{
					Mode: "head",
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

			got, err := r.verifyCommitSignature(context.TODO(), obj, tt.commit)
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestGitRepositoryReconciler_getProxyOpts(t *testing.T) {
	invalidProxy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-proxy",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"url": []byte("https://example.com"),
		},
	}
	validProxy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-proxy",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"address":  []byte("https://example.com"),
			"username": []byte("user"),
			"password": []byte("pass"),
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithObjects(invalidProxy, validProxy)

	r := &GitRepositoryReconciler{
		Client: clientBuilder.Build(),
	}

	tests := []struct {
		name      string
		secret    string
		err       string
		proxyOpts *transport.ProxyOptions
	}{
		{
			name:   "non-existent secret",
			secret: "non-existent",
			err:    "failed to get proxy secret 'default/non-existent': ",
		},
		{
			name:   "invalid proxy secret",
			secret: "invalid-proxy",
			err:    "invalid proxy secret 'default/invalid-proxy': key 'address' is missing",
		},
		{
			name:   "valid proxy secret",
			secret: "valid-proxy",
			proxyOpts: &transport.ProxyOptions{
				URL:      "https://example.com",
				Username: "user",
				Password: "pass",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			opts, err := r.getProxyOpts(context.TODO(), tt.secret, "default")
			if opts != nil {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(opts).To(Equal(tt.proxyOpts))
			} else {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
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
			recResult := sreconcile.ResultSuccess
			var retErr error

			summarizeHelper := summarize.NewHelper(record.NewFakeRecorder(32), serialPatcher)
			summarizeOpts := []summarize.Option{
				summarize.WithConditions(gitRepositoryReadyCondition),
				summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
				summarize.WithReconcileResult(recResult),
				summarize.WithReconcileError(retErr),
				summarize.WithIgnoreNotFound(),
				summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetRequeueAfter()}),
				summarize.WithPatchFieldOwner("source-controller"),
			}
			_, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

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
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
			},
			commit:    concreteCommit,
			wantEvent: "Normal NewArtifact stored artifact for commit 'test commit'",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
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
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Digest: "bbb"}
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
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
		{
			name:   "no-op error result",
			res:    sreconcile.ResultEmpty,
			resErr: noopErr,
			oldObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.GitRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
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
			wantArtifactSet: []*sourcev1.Artifact{
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
				*conditions.TrueCondition(sourcev1.IncludeUnavailableCondition, "NotFound", "could not get resource for include 'a': gitrepositories.source.toolkit.fluxcd.io \"a\" not found"),
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
					obj.Status.Artifact = &sourcev1.Artifact{
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
		artifacts []*sourcev1.Artifact
		want      bool
	}{
		{
			name: "no content config",
			want: false,
		},
		{
			name: "unobserved ignore",
			obj: sourcev1.GitRepository{
				Spec: sourcev1.GitRepositorySpec{Ignore: pointer.String("foo")},
			},
			want: true,
		},
		{
			name: "observed ignore",
			obj: sourcev1.GitRepository{
				Spec:   sourcev1.GitRepositorySpec{Ignore: pointer.String("foo")},
				Status: sourcev1.GitRepositoryStatus{ObservedIgnore: pointer.String("foo")},
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
					IncludedArtifacts: []*sourcev1.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{{Revision: "aaa", Digest: "bbb"}},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{
						{Revision: "aaa", Digest: "bbb"},
						{Revision: "ccc", Digest: "ccc"},
					},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{
						{Revision: "aaa", Digest: "bbb"},
						{Revision: "ccc", Digest: "ccc"},
					},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
					IncludedArtifacts: []*sourcev1.Artifact{
						{Revision: "aaa", Digest: "bbb"},
					},
				},
			},
			artifacts: []*sourcev1.Artifact{
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
