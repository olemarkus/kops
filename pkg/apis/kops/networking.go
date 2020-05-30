/*
Copyright 2019 The Kubernetes Authors.

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

package kops

import (
	"k8s.io/apimachinery/pkg/api/resource"
)

// NetworkingSpec allows selection and configuration of a networking plugin
type NetworkingSpec struct {
	Classic    *ClassicNetworkingSpec    `json:"classic,omitempty"`
	Kubenet    *KubenetNetworkingSpec    `json:"kubenet,omitempty"`
	External   *ExternalNetworkingSpec   `json:"external,omitempty"`
	CNI        *CNINetworkingSpec        `json:"cni,omitempty"`
	Kopeio     *KopeioNetworkingSpec     `json:"kopeio,omitempty"`
	Weave      *WeaveNetworkingSpec      `json:"weave,omitempty"`
	Flannel    *FlannelNetworkingSpec    `json:"flannel,omitempty"`
	Calico     *CalicoNetworkingSpec     `json:"calico,omitempty"`
	Canal      *CanalNetworkingSpec      `json:"canal,omitempty"`
	Kuberouter *KuberouterNetworkingSpec `json:"kuberouter,omitempty"`
	Romana     *RomanaNetworkingSpec     `json:"romana,omitempty"`
	AmazonVPC  *AmazonVPCNetworkingSpec  `json:"amazonvpc,omitempty"`
	Cilium     *CiliumNetworkingSpec     `json:"cilium,omitempty"`
	LyftVPC    *LyftVPCNetworkingSpec    `json:"lyftvpc,omitempty"`
	GCE        *GCENetworkingSpec        `json:"gce,omitempty"`
}

// ClassicNetworkingSpec is the specification of classic networking mode, integrated into kubernetes.
// Support been removed since Kubernetes 1.4.
type ClassicNetworkingSpec struct {
}

// KubenetNetworkingSpec is the specification for kubenet networking, largely integrated but intended to replace classic
type KubenetNetworkingSpec struct {
}

// ExternalNetworkingSpec is the specification for networking that is implemented by a user-provided Daemonset that uses the Kubenet kubelet networking plugin.
type ExternalNetworkingSpec struct {
}

// CNINetworkingSpec is the specification for networking that is implemented by a user-provided Daemonset, which uses the CNI kubelet networking plugin.
type CNINetworkingSpec struct {
	UsesSecondaryIP bool `json:"usesSecondaryIP,omitempty"`
}

// KopeioNetworkingSpec declares that we want Kopeio networking
type KopeioNetworkingSpec struct {
}

// WeaveNetworkingSpec declares that we want Weave networking
type WeaveNetworkingSpec struct {
	MTU         *int32 `json:"mtu,omitempty"`
	ConnLimit   *int32 `json:"connLimit,omitempty"`
	NoMasqLocal *int32 `json:"noMasqLocal,omitempty"`

	// MemoryRequest memory request of weave container. Default 200Mi
	MemoryRequest *resource.Quantity `json:"memoryRequest,omitempty"`
	// CPURequest CPU request of weave container. Default 50m
	CPURequest *resource.Quantity `json:"cpuRequest,omitempty"`
	// MemoryLimit memory limit of weave container. Default 200Mi
	MemoryLimit *resource.Quantity `json:"memoryLimit,omitempty"`
	// CPULimit CPU limit of weave container.
	CPULimit *resource.Quantity `json:"cpuLimit,omitempty"`
	// NetExtraArgs are extra arguments that are passed to weave-kube.
	NetExtraArgs string `json:"netExtraArgs,omitempty"`

	// NPCMemoryRequest memory request of weave npc container. Default 200Mi
	NPCMemoryRequest *resource.Quantity `json:"npcMemoryRequest,omitempty"`
	// NPCCPURequest CPU request of weave npc container. Default 50m
	NPCCPURequest *resource.Quantity `json:"npcCPURequest,omitempty"`
	// NPCMemoryLimit memory limit of weave npc container. Default 200Mi
	NPCMemoryLimit *resource.Quantity `json:"npcMemoryLimit,omitempty"`
	// NPCCPULimit CPU limit of weave npc container
	NPCCPULimit *resource.Quantity `json:"npcCPULimit,omitempty"`
	// NPCExtraArgs are extra arguments that are passed to weave-npc.
	NPCExtraArgs string `json:"npcExtraArgs,omitempty"`
}

// FlannelNetworkingSpec declares that we want Flannel networking
type FlannelNetworkingSpec struct {
	// Backend is the backend overlay type we want to use (vxlan or udp)
	Backend string `json:"backend,omitempty"`
	// IptablesResyncSeconds sets resync period for iptables rules, in seconds
	IptablesResyncSeconds *int32 `json:"iptablesResyncSeconds,omitempty"`
}

// CalicoNetworkingSpec declares that we want Calico networking
type CalicoNetworkingSpec struct {
	// CPURequest CPU request of Calico container. Default: 100m
	CPURequest *resource.Quantity `json:"cpuRequest,omitempty"`
	// CrossSubnet enables Calico's cross-subnet mode when set to true
	CrossSubnet bool `json:"crossSubnet,omitempty"`
	// LogSeverityScreen lets us set the desired log level. (Default: info)
	LogSeverityScreen string `json:"logSeverityScreen,omitempty"`
	// MTU to be set in the cni-network-config for calico.
	MTU *int32 `json:"mtu,omitempty"`
	// PrometheusMetricsEnabled can be set to enable the experimental Prometheus
	// metrics server (default: false)
	PrometheusMetricsEnabled bool `json:"prometheusMetricsEnabled,omitempty"`
	// PrometheusMetricsPort is the TCP port that the experimental Prometheus
	// metrics server should bind to (default: 9091)
	PrometheusMetricsPort int32 `json:"prometheusMetricsPort,omitempty"`
	// PrometheusGoMetricsEnabled enables Prometheus Go runtime metrics collection
	PrometheusGoMetricsEnabled bool `json:"prometheusGoMetricsEnabled,omitempty"`
	// PrometheusProcessMetricsEnabled enables Prometheus process metrics collection
	PrometheusProcessMetricsEnabled bool `json:"prometheusProcessMetricsEnabled,omitempty"`
	// MajorVersion is the version of Calico to use
	MajorVersion string `json:"majorVersion,omitempty"`
	// IptablesBackend controls which variant of iptables binary Felix uses
	// Default: Auto (other options: Legacy, NFT)
	IptablesBackend string `json:"iptablesBackend,omitempty"`
	// IPIPMode is mode for CALICO_IPV4POOL_IPIP
	IPIPMode string `json:"ipipMode,omitempty"`
	// TyphaPrometheusMetricsEnabled enables Prometheus metrics collection from Typha
	// (default: false)
	TyphaPrometheusMetricsEnabled bool `json:"typhaPrometheusMetricsEnabled,omitempty"`
	// TyphaPrometheusMetricsPort is the TCP port the typha Prometheus metrics server
	// should bind to (default: 9093)
	TyphaPrometheusMetricsPort int32 `json:"typhaPrometheusMetricsPort,omitempty"`
	// TyphaReplicas is the number of replicas of Typha to deploy
	TyphaReplicas int32 `json:"typhaReplicas,omitempty"`
}

// CanalNetworkingSpec declares that we want Canal networking
type CanalNetworkingSpec struct {
	// ChainInsertMode controls whether Felix inserts rules to the top of iptables chains, or
	// appends to the bottom. Leaving the default option is safest to prevent accidentally
	// breaking connectivity. Default: 'insert' (other options: 'append')
	ChainInsertMode string `json:"chainInsertMode,omitempty"`
	// CPURequest CPU request of Canal container. Default: 100m
	CPURequest *resource.Quantity `json:"cpuRequest,omitempty"`
	// DefaultEndpointToHostAction allows users to configure the default behaviour
	// for traffic between pod to host after calico rules have been processed.
	// Default: ACCEPT (other options: DROP, RETURN)
	DefaultEndpointToHostAction string `json:"defaultEndpointToHostAction,omitempty"`
	// DisableFlannelForwardRules configures Flannel to NOT add the
	// default ACCEPT traffic rules to the iptables FORWARD chain
	DisableFlannelForwardRules bool `json:"disableFlannelForwardRules,omitempty"`
	// IptablesBackend controls which variant of iptables binary Felix uses
	// Default: Auto (other options: Legacy, NFT)
	IptablesBackend string `json:"iptablesBackend,omitempty"`
	// LogSeveritySys the severity to set for logs which are sent to syslog
	// Default: INFO (other options: DEBUG, WARNING, ERROR, CRITICAL, NONE)
	LogSeveritySys string `json:"logSeveritySys,omitempty"`
	// MTU to be set in the cni-network-config (default: 1500)
	MTU *int32 `json:"mtu,omitempty"`
	// PrometheusGoMetricsEnabled enables Prometheus Go runtime metrics collection
	PrometheusGoMetricsEnabled bool `json:"prometheusGoMetricsEnabled,omitempty"`
	// PrometheusMetricsEnabled can be set to enable the experimental Prometheus
	// metrics server (default: false)
	PrometheusMetricsEnabled bool `json:"prometheusMetricsEnabled,omitempty"`
	// PrometheusMetricsPort is the TCP port that the experimental Prometheus
	// metrics server should bind to (default: 9091)
	PrometheusMetricsPort int32 `json:"prometheusMetricsPort,omitempty"`
	// PrometheusProcessMetricsEnabled enables Prometheus process metrics collection
	PrometheusProcessMetricsEnabled bool `json:"prometheusProcessMetricsEnabled,omitempty"`
	// TyphaPrometheusMetricsEnabled enables Prometheus metrics collection from Typha
	// (default: false)
	TyphaPrometheusMetricsEnabled bool `json:"typhaPrometheusMetricsEnabled,omitempty"`
	// TyphaPrometheusMetricsPort is the TCP port the typha Prometheus metrics server
	// should bind to (default: 9093)
	TyphaPrometheusMetricsPort int32 `json:"typhaPrometheusMetricsPort,omitempty"`
	// TyphaReplicas is the number of replicas of Typha to deploy
	TyphaReplicas int32 `json:"typhaReplicas,omitempty"`
}

// KuberouterNetworkingSpec declares that we want Kube-router networking
type KuberouterNetworkingSpec struct {
}

// RomanaNetworkingSpec declares that we want Romana networking
type RomanaNetworkingSpec struct {
	// DaemonServiceIP is the Kubernetes Service IP for the romana-daemon pod
	DaemonServiceIP string `json:"daemonServiceIP,omitempty"`
	// EtcdServiceIP is the Kubernetes Service IP for the etcd backend used by Romana
	EtcdServiceIP string `json:"etcdServiceIP,omitempty"`
}

// AmazonVPCNetworkingSpec declares that we want Amazon VPC CNI networking
type AmazonVPCNetworkingSpec struct {
	// The container image name to use
	ImageName string `json:"imageName,omitempty"`
	// Env is a list of environment variables to set in the container.
	Env []EnvVar `json:"env,omitempty"`
}

const CiliumIpamEni = "eni"

type CiliumNetworkingPrometheusSpec struct {
	// Enable enables the Cilium "/metrics" endpoint for both the agent and the operator.
	Enable bool `json:"enablePrometheusMetrics,omitempty"`
	// AgentPort is the port to listen to for Prometheus metrics.
	// Defaults to 9090.
	AgentPort int `json:"agentPrometheusPort,omitempty"`
}

// CiliumNetworkingSpec declares that we want Cilium networking
type CiliumNetworkingSpec struct {
	// Version is the version of the Cilium agent and the Cilium Operator.
	Version string `json:"version,omitempty"`

	Prometheus *CiliumNetworkingPrometheusSpec

	// Debug runs Cilium in debug mode.
	Debug bool `json:"debug,omitempty"`
	// EnablePolicy specifies the policy enforcement mode.
	// "default": Follows Kubernetes policy enforcement.
	// "always": Cilium restricts all traffic if no policy is in place.
	// "never": Cilium allows all traffic regardless of policies in place.
	// If unspecified, "default" policy mode will be used.
	EnablePolicy string `json:"enablePolicy,omitempty"`
	// DisableMasquerade disables masquerading traffic to external destinations behind the node IP.
	DisableMasquerade bool `json:"disableMasquerade,omitempty"`
	// Tunnel specifies the Cilium tunelling mode. Possible values are "vxlan", "geneve", or "disabled".
	// Default: vxlan
	Tunnel string `json:"tunnel,omitempty"`
	// EnableIpv6 enables cluster IPv6 traffic. If both EnableIpv6 and EnableIpv4 are set to false
	// then IPv4 will be enabled.
	// Default: false
	EnableIpv6 bool `json:"enableipv6"`
	// EnableIpv4 enables cluster IPv4 traffic. If both EnableIpv6 and EnableIpv4 are set to false
	// then IPv4 will be enabled.
	// Default: false
	EnableIpv4 bool `json:"enableipv4"`
	// MonitorAggregation sets the level of packet monitoring. Possible values are "low", "medium", or "maximum".
	// Default: medium
	MonitorAggregation string `json:"monitorAggregation"`
	// BPFCTGlobalTCPMax is the maximum number of entries in the TCP CT table.
	// Default: 524288
	BPFCTGlobalTCPMax int `json:"bpfCTGlobalTCPMax"`
	// BPFCTGlobalAnyMax is the maximum number of entries in the non-TCP CT table.
	// Default: 262144
	BPFCTGlobalAnyMax int `json:"bpfCTGlobalAnyMax"`
	// PreallocateBPFMaps reduces the per-packet latency at the expense of up-front memory allocation.
	// Default: true
	PreallocateBPFMaps bool `json:"preallocateBPFMaps"`
	// SidecarIstioProxyImage is the regular expression matching compatible Istio sidecar istio-proxy
	// container image names.
	// Default: cilium/istio_proxy
	SidecarIstioProxyImage string `json:"sidecarIstioProxyImage"`
	// ClusterName is the name of the cluster. It is only relevant when building a mesh of clusters.
	ClusterName string `json:"clusterName"`
	// ToFqdnsDNSRejectResponseCode sets the DNS response code for rejecting DNS requests.
	// Possible values are "nameError" or "refused".
	// Default: refused
	ToFqdnsDNSRejectResponseCode string `json:"toFqdnsDnsRejectResponseCode,omitempty"`
	// ToFqdnsEnablePoller replaces the DNS proxy-based implementation of FQDN policies
	// with the less powerful legacy implementation.
	// Default: false
	ToFqdnsEnablePoller bool `json:"toFqdnsEnablePoller"`
	// ContainerRuntimeLabels enables fetching of container-runtime labels from the specified container runtime and associating them with endpoints.
	// Supported values are: "none", "containerd", "crio", "docker", "auto"
	// As of Cilium 1.7.0, Cilium no longer fetches information from the
	// container runtime and this field is ignored.
	// Default: none
	ContainerRuntimeLabels string `json:"containerRuntimeLabels,omitempty"`
	// Ipam specifies the IP address allocation mode to use.
	// Possible values are "crd" and "eni".
	// "eni" will use AWS native networking for pods. Eni requires masquerade to be set to false.
	// "crd" will use CRDs for controlling IP address management.
	// Empty value will use host-scope address management.
	Ipam string `json:"ipam,omitempty"`
	// IPTablesRulesNoinstall disables installing the base IPTables rules used for masquerading and kube-proxy.
	// Default: false
	InstallIPTablesRules *bool `json:"installIPTablesRules,omitempty"`
	// AutoDirectNodeRoutes adds automatic L2 routing between nodes.
	// Default: false
	AutoDirectNodeRoutes bool `json:"autoDirectNodeRoutes,omitempty"`
	// EnableNodePort replaces kube-proxy with Cilium's BPF implementation.
	// Requires spec.kubeProxy.enabled be set to false.
	// Default: false
	EnableNodePort bool `json:"enableNodePort,omitempty"`
	// EtcdManagd installs an additional etcd cluster that is used for Cilium state change.
	// The cluster is operated by cilium-etcd-operator.
	// Default: false
	EtcdManaged bool `json:"etcdManaged,omitempty"`
	// EnableRemoteNodeIdentity enables the remote-node-identity added in Cilium 1.7.0.
	// Default: false
	EnableRemoteNodeIdentity bool `json:"enableRemoteNodeIdentity,omitempty"`
}

// LyftVPCNetworkingSpec declares that we want to use the cni-ipvlan-vpc-k8s CNI networking.
type LyftVPCNetworkingSpec struct {
	SubnetTags map[string]string `json:"subnetTags,omitempty"`
}

// GCENetworkingSpec is the specification of GCE's native networking mode, using IP aliases
type GCENetworkingSpec struct {
}
