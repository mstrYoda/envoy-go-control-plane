package main

import (
	"context"
	"fmt"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/duration"

	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	v31 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	envoy_config_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	extensions_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/grpc"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/golang/protobuf/ptypes"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
)

func main() {
	grpcServer := grpc.NewServer()
	lis, _ := net.Listen("tcp", ":18000")

	snapshotCache := cache.NewSnapshotCache(true, cache.IDHash{}, nil)
	server := xds.NewServer(context.Background(), snapshotCache, nil)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	go func() {
		snapshot := cache.NewSnapshot(
			"1",
			[]types.Resource{}, // endpoints
			[]types.Resource{makeCluster(ClusterName, uint32(8080)), makeCluster("ext_authz_cluster", uint32(9191))},
			[]types.Resource{}, // routes
			[]types.Resource{makeHTTPListener(ListenerName)},
			[]types.Resource{}, // runtimes
			[]types.Resource{}, // secrets
		)
		err := snapshotCache.SetSnapshot("test-id", snapshot)
		if err != nil {
			fmt.Println("Could not set snapshot %v", err)
		}
		fmt.Println("snapshot setted")
	}()
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Errorf("%v", err)
	}

}

const (
	ClusterName  = "example_proxy_cluster"
	RouteName    = "local_route"
	ListenerName = "listener_0"
	ListenerPort = 10000
	UpstreamHost = "192.168.1.4"
)

func makeCluster(clusterName string, port uint32) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       ptypes.DurationProto(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint(clusterName, port),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func makeEndpoint(clusterName string, port uint32) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  UpstreamHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: port,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeRoute(path string, exact bool, cluster string) *route.Route {
	var routeMatch *route.RouteMatch

	if exact {
		routeMatch = &route.RouteMatch{
			PathSpecifier:&route.RouteMatch_Path{
				Path: path,
			},
		}
	} else {
		routeMatch = &route.RouteMatch{
			PathSpecifier:&route.RouteMatch_Prefix{
				Prefix: path,
			},
		}
	}

	return &route.Route{
		Match: routeMatch,
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: cluster,
				},
			},
		},
	}
}

func makeExtAuthzFilter() *hcm.HttpFilter {
	extAuthz := &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
		Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_HttpService{
			HttpService: &envoy_extensions_filters_http_ext_authz_v3.HttpService{
				ServerUri: &core.HttpUri{
					Uri:     "http://192.168.1.4:9191",
					Timeout: &duration.Duration{Seconds: 600},
					HttpUpstreamType: &core.HttpUri_Cluster{
						Cluster: "ext_authz_cluster",
					},
				},
				PathPrefix: "/authorize",
			},
		},
		FailureModeAllow:    true,
		StatusOnError:       &v31.HttpStatus{Code: v31.StatusCode_FailedDependency},
		TransportApiVersion: core.ApiVersion_V3,
	}

	exAuthzPb, _ := ptypes.MarshalAny(extAuthz)

	return &hcm.HttpFilter{
		Name: wellknown.HTTPExternalAuthorization,
			ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: exAuthzPb,
		},
	}
}

func makeRbacFilter() *hcm.HttpFilter {
	policies := map[string]*envoy_config_rbac_v3.Policy{
		"rule-first-test": {
			Permissions: []*envoy_config_rbac_v3.Permission{
				permission_and(
					andRules(
						permission_or(orRules(headerPermission())),
						permission_or(orRules(pathMatcherExactPermission("/test"))))),
			},
			Principals: []*envoy_config_rbac_v3.Principal{
				principal_notId_or(),
			},
		},
	}

	pbrbac, err := ptypes.MarshalAny(rbac(envoy_config_rbac_v3.RBAC_DENY, policies))
	if err != nil {
		panic(err)
	}

	return &hcm.HttpFilter{
		Name: wellknown.HTTPRoleBasedAccessControl,
			ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: pbrbac,
		},
	}
}

func makeHTTPListener(listenerName string) *listener.Listener {
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &route.RouteConfiguration{
				Name: RouteName,
				VirtualHosts: []*route.VirtualHost{
					{
						Name:    "local_service",
						Domains: []string{"*"},
						Routes: []*route.Route{
							makeRoute("/", false, ClusterName),
						},
					},
				},
			},
		},
		HttpFilters: []*hcm.HttpFilter{
			makeRbacFilter(),
			//makeExtAuthzFilter(),
			{
				Name: wellknown.Router,
			},
		},
	}
	pbst, err := ptypes.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: ListenerPort,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				//TransportSocket: &core.TransportSocket{
				//	ConfigType: &core.TransportSocket_TypedConfig{
				//		TypedConfig: &anypb.Any{
				//			Value: func() []byte {
				//				tls := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
				//					CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
				//						TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
				//							{
				//								CertificateChain: &core.DataSource{
				//									Specifier: &core.DataSource_Filename{Filename: ""},
				//								},
				//								PrivateKey: &core.DataSource{
				//									Specifier: &core.DataSource_Filename{Filename: ""},
				//								},
				//							},
				//						},
				//					},
				//				}
				//				tlsMarsh, _ := ptypes.MarshalAny(tls)
				//				return tlsMarsh.Value
				//			}(),
				//		},
				//	},
				//},
				//FilterChainMatch: &listener.FilterChainMatch{
				//	ServerNames: []string{"*"},
				//	TransportProtocol: wellknown.TransportSocketTls,
				//},
				Filters: []*listener.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: pbst,
						},
					},
				},
			}},
	}
}

/*
RBAC(
	Permissions()
		AndRules(
			OrRules(permissions),
			OrRules(permissions),
	),
	Principals(
		NotId(
			OrIds(principals)
		)
	)
)
*/

func generateHeaderMatcher(name, value string) *route.HeaderMatcher {
	return &route.HeaderMatcher{
		Name: name,
		HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
			ExactMatch: value,
		},
	}
}

func headerPermission() *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_Header{
			Header: generateHeaderMatcher(":method", "GET"),
		},
	}
}

func pathMatcherPermission(regex string) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_UrlPath{
			UrlPath: &envoy_type_matcher_v3.PathMatcher{
				Rule: &envoy_type_matcher_v3.PathMatcher_Path{
					Path: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
							SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
								Regex: regex,
								EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
									GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
								},
							},
						},
					},
				},
			},
		},
	}
}

func pathMatcherExactPermission(path string) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_UrlPath{
			UrlPath: &envoy_type_matcher_v3.PathMatcher{
				Rule: &envoy_type_matcher_v3.PathMatcher_Path{
					Path: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: path,
						},
					},
				},
			},
		},
	}
}

func orRules(permissions ...*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission_OrRules {
	return &envoy_config_rbac_v3.Permission_OrRules{
		OrRules: &envoy_config_rbac_v3.Permission_Set{
			Rules: permissions,
		},
	}
}

func andRules(permissions ...*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission_AndRules {
	return &envoy_config_rbac_v3.Permission_AndRules{
		AndRules: &envoy_config_rbac_v3.Permission_Set{
			Rules: permissions,
		},
	}
}

func permission_or(or *envoy_config_rbac_v3.Permission_OrRules) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: or,
	}
}

func permission_and(and *envoy_config_rbac_v3.Permission_AndRules) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: and,
	}
}

func orIds(principals ...*envoy_config_rbac_v3.Principal) *envoy_config_rbac_v3.Principal_OrIds {
	return &envoy_config_rbac_v3.Principal_OrIds{
		OrIds: &envoy_config_rbac_v3.Principal_Set{
			Ids: principals,
		},
	}
}

func exactHeaderPrincipal() *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_Header{
			Header: generateHeaderMatcher("test-header", "test-value"),
		},
	}
}

func principal_notId_or() *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_NotId{
			NotId: &envoy_config_rbac_v3.Principal{
				Identifier: orIds(exactHeaderPrincipal()),
			},
		},
	}
}

func rbac(action envoy_config_rbac_v3.RBAC_Action, policies map[string]*envoy_config_rbac_v3.Policy) *extensions_rbac_v3.RBAC {
	return &extensions_rbac_v3.RBAC{
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}
