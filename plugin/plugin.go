package plugin

// Copyright 2020 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

import (
	"github.com/open-policy-agent/opa/plugins"

	"github.com/open-policy-agent/opa-envoy-plugin/inbound"
)

// Factory defines the interface OPA uses to instantiate a plugin.
type Factory struct{}

// PluginName is the name to register with the OPA plugin manager
// const PluginName = internal.PluginName
const PluginName = inbound.PluginName

// New returns the object initialized with a valid plugin configuration.
func (Factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return inbound.New(m, config.(*inbound.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (Factory) Validate(m *plugins.Manager, config []byte) (interface{}, error) {
	return inbound.Validate(m, config)
}
