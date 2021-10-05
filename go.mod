module github.com/fluxcd/source-controller

go 1.16

replace github.com/fluxcd/source-controller/api => ./api

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/fluxcd/pkg/apis/meta v0.11.0-rc.1
	github.com/fluxcd/pkg/gittestserver v0.4.0
	github.com/fluxcd/pkg/gitutil v0.1.0
	github.com/fluxcd/pkg/helmtestserver v0.2.0
	github.com/fluxcd/pkg/lockedfile v0.1.0
	github.com/fluxcd/pkg/runtime v0.13.0-rc.3
	github.com/fluxcd/pkg/ssh v0.1.0
	github.com/fluxcd/pkg/testserver v0.1.0
	github.com/fluxcd/pkg/untar v0.1.0
	github.com/fluxcd/pkg/version v0.1.0
	github.com/fluxcd/source-controller/api v0.15.3
	github.com/go-git/go-billy/v5 v5.3.1
	github.com/go-git/go-git/v5 v5.4.2
	github.com/go-logr/logr v0.4.0
	github.com/libgit2/git2go/v31 v31.4.14
	github.com/minio/minio-go/v7 v7.0.10
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gotest.tools v2.2.0+incompatible
	helm.sh/helm/v3 v3.6.3
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	k8s.io/utils v0.0.0-20210527160623-6fdb442a123b
	sigs.k8s.io/controller-runtime v0.9.3
	sigs.k8s.io/yaml v1.2.0
)

// required by https://github.com/helm/helm/blob/v3.6.0/go.mod
replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d
