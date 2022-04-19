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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/imdario/mergo"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/types"
)

// LoadConf parses and validates stdin netconf and returns NetConf object
func LoadConf(data []byte) (*types.NetConf, error) {
	netconf, err := loadNetConf(data)
	if err != nil {
		return nil, err
	}
	flatNetConf, err := loadFlatNetConf(netconf.ConfigurationPath)
	if err != nil {
		return nil, err
	}
	netconf, err = mergeConf(netconf, flatNetConf)
	if err != nil {
		return nil, err
	}
	return netconf, nil
}

func loadNetConf(bytes []byte) (*types.NetConf, error) {
	netconf := &types.NetConf{}
	if err := json.Unmarshal(bytes, netconf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	return netconf, nil
}

func loadFlatNetConf(configPath string) (*types.NetConf, error) {
	confFiles := getOvsConfFiles()
	if configPath != "" {
		confFiles = append([]string{configPath}, confFiles...)
	}

	// loop through the path and parse the JSON config
	flatNetConf := &types.NetConf{}
	for _, confFile := range confFiles {
		confExists, err := pathExists(confFile)
		if err != nil {
			return nil, fmt.Errorf("error checking ovs config file: error: %v", err)
		}
		if confExists {
			jsonFile, err := os.Open(confFile)
			if err != nil {
				return nil, fmt.Errorf("open ovs config file %s error: %v", confFile, err)
			}
			defer jsonFile.Close()
			jsonBytes, err := ioutil.ReadAll(jsonFile)
			if err != nil {
				return nil, fmt.Errorf("load ovs config file %s: error: %v", confFile, err)
			}
			if err := json.Unmarshal(jsonBytes, flatNetConf); err != nil {
				return nil, fmt.Errorf("parse ovs config file %s: error: %v", confFile, err)
			}
			break
		}
	}

	return flatNetConf, nil
}

func mergeConf(netconf, flatNetConf *types.NetConf) (*types.NetConf, error) {
	if err := mergo.Merge(netconf, flatNetConf); err != nil {
		return nil, fmt.Errorf("merge with ovs config file: error: %v", err)
	}
	return netconf, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func getOvsConfFiles() []string {
	return []string{"/etc/kubernetes/cni/net.d/ovs.d/ovs.conf", "/etc/cni/net.d/ovs.d/ovs.conf"}
}
