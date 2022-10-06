# Custom-plugin

The base code is cloned from Open Policy Agent Official Repositor #Custom-plugin
The base code is cloned from offical Open policy agent repository https://github.com/open-policy-agent/opa-envoy-plugin

## How to start the plugin
 `go run main.go run -s  --addr 192.168.163.1:8181 -l debug --set=plugins.custom_auth_grpc.addr=:9191 --set=plugins.custom_auth_grpc.syncservice-addr=http://localhost:3000/environments --set=plugins.custom_auth_grpc.sync-time-interval=10`

## How to build binary
### For window
 `set GOOS=windows`
 `set GOARCH=amd64`
 `go build`

### For Linux
 `set GOOS=linux`
 `set GOARCH=amd64`
 `go build`