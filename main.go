package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/runtime"
)

func main() {

	runtime.RegisterPlugin("custom_auth_grpc", plugin.Factory{}) //custom plugin

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
