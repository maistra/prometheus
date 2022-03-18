module github.com/prometheus/prometheus

go 1.13

require (
	github.com/Azure/azure-sdk-for-go v23.2.0+incompatible
	github.com/Azure/go-autorest v12.0.0+incompatible
	github.com/alecthomas/units v0.0.0-20190717042225-c3de453c63f4
	github.com/aws/aws-sdk-go v1.23.12
	github.com/cespare/xxhash v1.1.0
	github.com/dgryski/go-sip13 v0.0.0-20190329191031-25c5027a8c7b
	github.com/edsrzf/mmap-go v1.0.0
	github.com/go-kit/kit v0.9.0
	github.com/go-logfmt/logfmt v0.4.0
	github.com/go-openapi/strfmt v0.19.2
	github.com/gogo/protobuf v1.3.0
	github.com/golang/snappy v0.0.1
	github.com/google/pprof v0.0.0-20190723021845-34ac40c74b70
	github.com/gophercloud/gophercloud v0.3.0
	github.com/grpc-ecosystem/grpc-gateway v1.9.5
	github.com/hashicorp/consul v1.3.0
	github.com/influxdata/influxdb v1.7.7
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.7
	github.com/miekg/dns v1.1.15
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f
	github.com/oklog/run v1.0.0
	github.com/oklog/ulid v1.3.1
	github.com/opentracing-contrib/go-stdlib v0.0.0-20190519235532-cf7a6c988dc9
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/alertmanager v0.18.0
	github.com/prometheus/client_golang v1.2.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common v0.7.0
	github.com/samuel/go-zookeeper v0.0.0-20190810000440-0ceca61e4d75
	github.com/shurcooL/httpfs v0.0.0-20190707220628-8d4bc4ba7749
	github.com/shurcooL/vfsgen v0.0.0-20181202132449-6a9ea43bcacd
	github.com/soheilhy/cmux v0.1.4
	go.opencensus.io v0.22.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/tools v0.0.0-20191029190741-b9c20aec41a5
	google.golang.org/api v0.8.0
	google.golang.org/genproto v0.0.0-20191009194640-548a555dbc03
	google.golang.org/grpc v1.24.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	gopkg.in/yaml.v2 v2.2.4
	istio.io/istio v0.0.0-20190628021817-0cf9ca07c742
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog v0.4.0
)

replace (
	// this line fixes an issue with Azure dependencies
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v11.9.0+incompatible
	github.com/golang/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved
	istio.io/istio => github.com/maistra/istio v0.0.0-20200122191435-b0f47f26fa67

	// the following replace directives are copied from maistra/istio because
	// go mod ignores sub-module replace directives
	k8s.io/api => k8s.io/api v0.0.0-20191003000013-35e20aa79eb8
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191003002041-49e3d608220c
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191003001037-3c8b233e046c
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20191003002408-6e42c232ac7d
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918200256-06eb1244587a
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20191003003426-b4b1f434fead
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20191003003255-c493acd9e2ff
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190927045949-f81bca4f5e85
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191003000551-f573d376509c
	k8s.io/cri-api => k8s.io/cri-api v0.0.0-20190828162817-608eb1dad4ac
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20191003003551-0eecdcdcc049
	k8s.io/klog => github.com/simonpasquier/klog-gokit v0.1.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191003001317-a019a9d85a86
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20191003003129-09316795c0dd
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20191003002707-f6b7b0f55cc0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20191003003001-314f0beee0a9
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20191003002833-e367e4712542
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20191003003732-7d49cdad1c12
	k8s.io/metrics => k8s.io/metrics v0.0.0-20191003002233-837aead57baf
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20191003001538-80f33ca02582
)
