module github.com/fluxcd/source-controller

go 1.16

replace github.com/fluxcd/source-controller/api => ./api

require (
	cloud.google.com/go v0.93.3 // indirect
	cloud.google.com/go/storage v1.16.0
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7
	github.com/bshuster-repo/logrus-logstash-hook v1.0.2 // indirect
	github.com/bugsnag/bugsnag-go v2.1.2+incompatible // indirect
	github.com/bugsnag/panicwrap v1.3.4 // indirect
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/fluxcd/pkg/apis/meta v0.10.1
	github.com/fluxcd/pkg/gittestserver v0.4.2
	github.com/fluxcd/pkg/gitutil v0.1.0
	github.com/fluxcd/pkg/helmtestserver v0.2.0
	github.com/fluxcd/pkg/lockedfile v0.1.0
	github.com/fluxcd/pkg/runtime v0.12.0
	github.com/fluxcd/pkg/ssh v0.1.0
	github.com/fluxcd/pkg/untar v0.1.0
	github.com/fluxcd/pkg/version v0.1.0
	github.com/fluxcd/source-controller/api v0.19.2
	github.com/garyburd/redigo v1.6.3 // indirect
	github.com/go-git/go-billy/v5 v5.3.1
	github.com/go-git/go-git/v5 v5.4.2
	github.com/go-logr/logr v0.4.0
	github.com/gofrs/uuid v4.1.0+incompatible // indirect
	github.com/googleapis/gax-go/v2 v2.1.0 // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/libgit2/git2go/v31 v31.6.1
	github.com/minio/minio-go/v7 v7.0.15
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	github.com/otiai10/copy v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/yvasiyarov/go-metrics v0.0.0-20150112132944-c25f46c4b940 // indirect
	github.com/yvasiyarov/gorelic v0.0.7 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20160601141957-9c099fbc30e9 // indirect
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/net v0.0.0-20210825183410-e898025ed96a // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/api v0.54.0
	google.golang.org/genproto v0.0.0-20210830153122-0bac4d21c8ea // indirect
	gotest.tools v2.2.0+incompatible
	helm.sh/helm/v3 v3.6.3
	k8s.io/api v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/client-go v0.22.2
	sigs.k8s.io/controller-runtime v0.10.2
	sigs.k8s.io/yaml v1.2.0
)

// Required by https://github.com/helm/helm/blob/v3.6.3/go.mod,
// but overwritten with a newer version due to CVE-2017-11468.
replace github.com/docker/distribution => github.com/docker/distribution v2.7.0-rc.0+incompatible

// Fix CVE-2021-41092
replace github.com/docker/cli => github.com/docker/cli v20.10.9+incompatible

// Fix CVE-2021-41103
// Fix CVE-2021-41190
replace github.com/containerd/containerd => github.com/containerd/containerd v1.4.12

// Fix CVE-2021-30465
// Fix CVE-2021-43784
// Fix GO-2021-0085
// Fix GO-2021-0087
replace github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.3

// Fix CVE-2021-41190
replace github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.2
