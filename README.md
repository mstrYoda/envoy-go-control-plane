# envoy-go-control-plane
An example to dynamic configuration of Envoy Proxy using go-control-plane.

### Run Envoy Proxy With Control Plane

```docker run -it --rm -v "$PWD"/envoy-custom.yaml:/etc/envoy/envoy.yaml -p 9901:9901 -p 10000:10000 envoyproxy/envoy:v1.17.0```

### How Istio Use Envoy Proxy

- [go-control-plane](https://github.com/envoyproxy/go-control-plane)

![Istio Mesh](istio.png)

### Envoy Extensibility

- [Envoy Ext Authz Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
- [Extending Envoy with WASM](https://medium.com/trendyol-tech/extending-envoy-proxy-wasm-filter-with-golang-9080017f28ea)
- [Envoy Lua Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/lua_filter)
- [OPA Envoy Plugin](https://github.com/open-policy-agent/opa-envoy-plugin)