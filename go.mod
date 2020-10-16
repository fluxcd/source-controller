module github.com/fluxcd/source-controller

go 1.15

replace github.com/fluxcd/source-controller/api => ./api

require (
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/fluxcd/pkg/apis/meta v0.0.2
	github.com/fluxcd/pkg/gittestserver v0.0.2
	github.com/fluxcd/pkg/helmtestserver v0.0.1
	github.com/fluxcd/pkg/lockedfile v0.0.5
	github.com/fluxcd/pkg/runtime v0.1.0
	github.com/fluxcd/pkg/ssh v0.0.5
	github.com/fluxcd/pkg/untar v0.0.5
	github.com/fluxcd/source-controller/api v0.1.1
	github.com/go-git/go-billy/v5 v5.0.0
	github.com/go-git/go-git/v5 v5.1.0
	github.com/go-logr/logr v0.1.0
	github.com/minio/minio-go/v7 v7.0.5
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	helm.sh/helm/v3 v3.3.4
	k8s.io/api v0.18.9
	k8s.io/apimachinery v0.18.9
	k8s.io/client-go v0.18.9
	sigs.k8s.io/controller-runtime v0.6.3
	sigs.k8s.io/yaml v1.2.0
)
