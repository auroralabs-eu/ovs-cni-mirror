// Copyright (c) 2021 Red Hat, Inc.
// Copyright (c) 2021 CNI authors
// Copyright (c) 2021 Nordix Foundation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// NetConf extends types.NetConf for ovs-cni
type NetConf struct {
	types.NetConf

	// support chaining for master interface and IP decisions
	// occurring prior to running ipvlan plugin
	// TODO types.NetConf already define this field, so We should use it instead of re-define it
	PrevResult *current.Result `json:"prevResult"`

	BrName            string    `json:"bridge,omitempty"`
	ConfigurationPath string    `json:"configuration_path"`
	SocketFile        string    `json:"socket_file"`
	Mirrors           []*Mirror `json:"mirrors,omitempty"`
}

type Mirror struct {
	Name    string `json:"name"`
	Ingress bool   `json:"ingress,omitempty"`
	Egress  bool   `json:"egress,omitempty"`
}
