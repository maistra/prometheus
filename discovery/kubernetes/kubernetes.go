// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"
	"istio.io/istio/pkg/listwatch"
	"istio.io/istio/pkg/servicemesh/controller"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery/targetgroup"

	apiv1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	// kubernetesMetaLabelPrefix is the meta prefix used for all meta labels.
	// in this discovery.
	metaLabelPrefix  = model.MetaLabelPrefix + "kubernetes_"
	namespaceLabel   = metaLabelPrefix + "namespace"
	metricsNamespace = "prometheus_sd_kubernetes"
)

var (
	// Custom events metric
	eventCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "events_total",
			Help:      "The number of Kubernetes events handled.",
		},
		[]string{"role", "event"},
	)
	// DefaultSDConfig is the default Kubernetes SD configuration
	DefaultSDConfig = SDConfig{}
)

// Role is role of the service in Kubernetes.
type Role string

// The valid options for Role.
const (
	RoleNode     Role = "node"
	RolePod      Role = "pod"
	RoleService  Role = "service"
	RoleEndpoint Role = "endpoints"
	RoleIngress  Role = "ingress"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Role) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if err := unmarshal((*string)(c)); err != nil {
		return err
	}
	switch *c {
	case RoleNode, RolePod, RoleService, RoleEndpoint, RoleIngress:
		return nil
	default:
		return fmt.Errorf("unknown Kubernetes SD role %q", *c)
	}
}

// SDConfig is the configuration for Kubernetes service discovery.
type SDConfig struct {
	APIServer          config_util.URL        `yaml:"api_server,omitempty"`
	Role               Role                   `yaml:"role"`
	BasicAuth          *config_util.BasicAuth `yaml:"basic_auth,omitempty"`
	BearerToken        config_util.Secret     `yaml:"bearer_token,omitempty"`
	BearerTokenFile    string                 `yaml:"bearer_token_file,omitempty"`
	TLSConfig          config_util.TLSConfig  `yaml:"tls_config,omitempty"`
	NamespaceDiscovery NamespaceDiscovery     `yaml:"namespaces,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SDConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = SDConfig{}
	type plain SDConfig
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	if c.Role == "" {
		return fmt.Errorf("role missing (one of: pod, service, endpoints, node, ingress)")
	}
	if len(c.BearerToken) > 0 && len(c.BearerTokenFile) > 0 {
		return fmt.Errorf("at most one of bearer_token & bearer_token_file must be configured")
	}
	if c.BasicAuth != nil && (len(c.BearerToken) > 0 || len(c.BearerTokenFile) > 0) {
		return fmt.Errorf("at most one of basic_auth, bearer_token & bearer_token_file must be configured")
	}
	if c.APIServer.URL == nil &&
		(c.BasicAuth != nil || c.BearerToken != "" || c.BearerTokenFile != "" ||
			c.TLSConfig.CAFile != "" || c.TLSConfig.CertFile != "" || c.TLSConfig.KeyFile != "") {
		return fmt.Errorf("to use custom authentication please provide the 'api_server' URL explicitly")
	}
	return nil
}

// NamespaceDiscovery is the configuration for discovering
// Kubernetes namespaces.
type NamespaceDiscovery struct {
	Names []string `yaml:"names"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *NamespaceDiscovery) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = NamespaceDiscovery{}
	type plain NamespaceDiscovery
	return unmarshal((*plain)(c))
}

func init() {
	prometheus.MustRegister(eventCount)

	// Initialize metric vectors.
	for _, role := range []string{"endpoints", "node", "pod", "service", "ingress"} {
		for _, evt := range []string{"add", "delete", "update"} {
			eventCount.WithLabelValues(role, evt)
		}
	}

	var (
		clientGoRequestMetricAdapterInstance     = clientGoRequestMetricAdapter{}
		clientGoCacheMetricsProviderInstance     = clientGoCacheMetricsProvider{}
		clientGoWorkqueueMetricsProviderInstance = clientGoWorkqueueMetricsProvider{}
	)

	clientGoRequestMetricAdapterInstance.Register(prometheus.DefaultRegisterer)
	clientGoCacheMetricsProviderInstance.Register(prometheus.DefaultRegisterer)
	clientGoWorkqueueMetricsProviderInstance.Register(prometheus.DefaultRegisterer)

}

// This is only for internal use.
type discoverer interface {
	Run(ctx context.Context, up chan<- []*targetgroup.Group)
}

// Discovery implements the discoverer interface for discovering
// targets from Kubernetes.
type Discovery struct {
	sync.RWMutex
	client               kubernetes.Interface
	role                 Role
	logger               log.Logger
	namespaceDiscovery   *NamespaceDiscovery
	discoverers          []discoverer
	memberRollNamespace  string
	memberRollController controller.MemberRollController
	memberRollResync     time.Duration
}

func (d *Discovery) getNamespaces() []string {
	namespaces := d.namespaceDiscovery.Names
	if len(namespaces) == 0 {
		namespaces = []string{apiv1.NamespaceAll}
	}
	return namespaces
}

// New creates a new Kubernetes discovery for the given role.
func New(l log.Logger, conf *SDConfig, memberRollController controller.MemberRollController,
	memberRollNamespace string, memberRollResync time.Duration) (*Discovery, error) {
	if l == nil {
		l = log.NewNopLogger()
	}
	var (
		kcfg *rest.Config
		err  error
	)
	if conf.APIServer.URL == nil {
		// Use the Kubernetes provided pod service account
		// as described in https://kubernetes.io/docs/admin/service-accounts-admin/
		kcfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		// Because the handling of configuration parameters changes
		// we should inform the user when their currently configured values
		// will be ignored due to precedence of InClusterConfig
		level.Info(l).Log("msg", "Using pod service account via in-cluster config")

		if conf.TLSConfig.CAFile != "" {
			level.Warn(l).Log("msg", "Configured TLS CA file is ignored when using pod service account")
		}
		if conf.TLSConfig.CertFile != "" || conf.TLSConfig.KeyFile != "" {
			level.Warn(l).Log("msg", "Configured TLS client certificate is ignored when using pod service account")
		}
		if conf.BearerToken != "" {
			level.Warn(l).Log("msg", "Configured auth token is ignored when using pod service account")
		}
		if conf.BasicAuth != nil {
			level.Warn(l).Log("msg", "Configured basic authentication credentials are ignored when using pod service account")
		}
	} else {
		kcfg = &rest.Config{
			Host: conf.APIServer.String(),
			TLSClientConfig: rest.TLSClientConfig{
				CAFile:   conf.TLSConfig.CAFile,
				CertFile: conf.TLSConfig.CertFile,
				KeyFile:  conf.TLSConfig.KeyFile,
				Insecure: conf.TLSConfig.InsecureSkipVerify,
			},
		}
		token := string(conf.BearerToken)
		if conf.BearerTokenFile != "" {
			bf, err := ioutil.ReadFile(conf.BearerTokenFile)
			if err != nil {
				return nil, err
			}
			token = string(bf)
		}
		kcfg.BearerToken = token

		if conf.BasicAuth != nil {
			kcfg.Username = conf.BasicAuth.Username
			kcfg.Password = string(conf.BasicAuth.Password)
		}
	}

	kcfg.UserAgent = "Prometheus/discovery"

	c, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return nil, err
	}
	return &Discovery{
		client:               c,
		logger:               l,
		role:                 conf.Role,
		namespaceDiscovery:   &conf.NamespaceDiscovery,
		discoverers:          make([]discoverer, 0),
		memberRollNamespace:  memberRollNamespace,
		memberRollController: memberRollController,
		memberRollResync:     memberRollResync,
	}, nil
}

const resyncPeriod = 10 * time.Minute

// Run implements the discoverer interface.
func (d *Discovery) Run(ctx context.Context, ch chan<- []*targetgroup.Group) {
	d.Lock()
	var namespaces []string
	if d.memberRollNamespace != "" && d.memberRollController != nil {
		namespaces = []string{d.memberRollNamespace}
	} else {
		namespaces = d.getNamespaces()
	}

	switch d.role {
	case RoleEndpoint:
		elw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.CoreV1().Endpoints(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.CoreV1().Endpoints(namespace).Watch(opts)
				},
			}
		}
		emnlw := listwatch.MultiNamespaceListerWatcher(namespaces, elw)
		if d.memberRollController != nil {
			d.memberRollController.Register(emnlw)
		}
		epInformer := cache.NewSharedIndexInformer(emnlw, &apiv1.Endpoints{}, d.memberRollResync, cache.Indexers{})

		slw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.CoreV1().Services(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.CoreV1().Services(namespace).Watch(opts)
				},
			}
		}
		smnlw := listwatch.MultiNamespaceListerWatcher(namespaces, slw)
		if d.memberRollController != nil {
			d.memberRollController.Register(smnlw)
		}
		svcInformer := cache.NewSharedIndexInformer(smnlw, &apiv1.Service{}, d.memberRollResync, cache.Indexers{})

		plw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.CoreV1().Pods(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.CoreV1().Pods(namespace).Watch(opts)
				},
			}
		}
		pmnlw := listwatch.MultiNamespaceListerWatcher(namespaces, plw)
		if d.memberRollController != nil {
			d.memberRollController.Register(pmnlw)
		}
		pInformer := cache.NewSharedIndexInformer(pmnlw, &apiv1.Pod{}, d.memberRollResync, cache.Indexers{})
		eps := NewEndpoints(
			log.With(d.logger, "role", "endpoint"),
			svcInformer,
			epInformer,
			pInformer,
		)
		d.discoverers = append(d.discoverers, eps)
		go eps.endpointsInf.Run(ctx.Done())
		go eps.serviceInf.Run(ctx.Done())
		go eps.podInf.Run(ctx.Done())
	case RolePod:
		plw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.CoreV1().Pods(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.CoreV1().Pods(namespace).Watch(opts)
				},
			}
		}
		pmnlw := listwatch.MultiNamespaceListerWatcher(namespaces, plw)
		if d.memberRollController != nil {
			d.memberRollController.Register(pmnlw)
		}
		pInformer := cache.NewSharedIndexInformer(pmnlw, &apiv1.Pod{}, d.memberRollResync, cache.Indexers{})
		pod := NewPod(
			log.With(d.logger, "role", "pod"),
			pInformer,
		)
		d.discoverers = append(d.discoverers, pod)
		go pod.informer.Run(ctx.Done())
	case RoleService:
		slw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.CoreV1().Services(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.CoreV1().Services(namespace).Watch(opts)
				},
			}
		}
		smnlw := listwatch.MultiNamespaceListerWatcher(namespaces, slw)
		if d.memberRollController != nil {
			d.memberRollController.Register(smnlw)
		}
		svcInformer := cache.NewSharedIndexInformer(smnlw, &apiv1.Service{}, d.memberRollResync, cache.Indexers{})
		svc := NewService(
			log.With(d.logger, "role", "service"),
			svcInformer,
		)
		d.discoverers = append(d.discoverers, svc)
		go svc.informer.Run(ctx.Done())
	case RoleIngress:
		ilw := func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
					return d.client.ExtensionsV1beta1().Ingresses(namespace).List(opts)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					return d.client.ExtensionsV1beta1().Ingresses(namespace).Watch(opts)
				},
			}
		}
		imnlw := listwatch.MultiNamespaceListerWatcher(namespaces, ilw)
		if d.memberRollController != nil {
			d.memberRollController.Register(imnlw)
		}
		ingressInformer := cache.NewSharedIndexInformer(imnlw, &extensionsv1beta1.Ingress{}, d.memberRollResync, cache.Indexers{})
		ingress := NewIngress(
			log.With(d.logger, "role", "ingress"),
			ingressInformer,
		)
		d.discoverers = append(d.discoverers, ingress)
		go ingress.informer.Run(ctx.Done())
	case RoleNode:
		nlw := &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return d.client.CoreV1().Nodes().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return d.client.CoreV1().Nodes().Watch(options)
			},
		}
		node := NewNode(
			log.With(d.logger, "role", "node"),
			cache.NewSharedInformer(nlw, &apiv1.Node{}, resyncPeriod),
		)
		d.discoverers = append(d.discoverers, node)
		go node.informer.Run(ctx.Done())
	default:
		level.Error(d.logger).Log("msg", "unknown Kubernetes discovery kind", "role", d.role)
	}

	var wg sync.WaitGroup
	for _, dd := range d.discoverers {
		wg.Add(1)
		go func(d discoverer) {
			defer wg.Done()
			d.Run(ctx, ch)
		}(dd)
	}

	d.Unlock()

	wg.Wait()
	<-ctx.Done()
}

func lv(s string) model.LabelValue {
	return model.LabelValue(s)
}

func send(ctx context.Context, l log.Logger, role Role, ch chan<- []*targetgroup.Group, tg *targetgroup.Group) {
	if tg == nil {
		return
	}
	select {
	case <-ctx.Done():
	case ch <- []*targetgroup.Group{tg}:
	}
}
