// Copyright 2018-2019 Red Hat, Inc.
// Copyright 2014 CNI authors
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

// Go version 1.10 or greater is required. Before that, switching namespaces in
// long running processes in go did not work in a reliable way.
//go:build go1.10
// +build go1.10

package plugin

import (
	"errors"
	"fmt"
	"log"
	"runtime"

	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/config"
	"go.uber.org/zap"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/ovsdb"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/types"
)

var logger *zap.SugaredLogger

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	logger = InitLogger("/home/master/ovs-logs/consumer.log")
	defer logger.Sync()
	logger.Info("Starting PLUGIN....")
}

func logCall(command string, args *skel.CmdArgs) {
	log.Printf("CNI %s was called for container ID: %s, network namespace %s, interface name %s, configuration: %s",
		command, args.ContainerID, args.Netns, args.IfName, string(args.StdinData[:]))
}

func getPortUUID(ovsDriver *ovsdb.OvsBridgeDriver, interfaces []*current.Interface) (string, error) {
	for _, iface := range interfaces {
		uuid, err := ovsDriver.GetPortUUID(iface.Name)
		if err == nil {
			return uuid.GoUUID, nil
		}
	}

	return "", errors.New("cannot find port in db")
}

func attachPortToMirror(ovsDriver *ovsdb.OvsBridgeDriver, portUUIDStr string, mirror *types.Mirror) error {
	err := ovsDriver.AttachPortToMirrorConsumer(portUUIDStr, mirror.Name)
	if err != nil {
		return err
	}

	return nil
}

func detachPortFromMirror(ovsDriver *ovsdb.OvsBridgeDriver, portUUIDStr string, mirror *types.Mirror) error {
	err := ovsDriver.DetachPortFromMirror(portUUIDStr, mirror.Name)
	if err != nil {
		return err
	}

	return nil
}

// CmdAdd add handler for attaching container into network
func CmdAdd(args *skel.CmdArgs) error {
	logCall("ADD", args)
	logger.Info("--------------cmdAdd--------------")
	logger.Info(args.IfName)
	logger.Info(args.ContainerID)
	logger.Info(args.Netns)
	logger.Info(args.Args)
	logger.Info(args.Path)
	logger.Info(fmt.Sprintf("the config data: %s\n", args.StdinData))

	netconf, err := config.LoadConf(args.StdinData)
	if err != nil {
		return err
	}
	logger.Infof("cmdAdd - netconf parsed from StdinData is: %#v", netconf)

	ovsDriver, err := ovsdb.NewOvsBridgeDriver(netconf.BrName, netconf.SocketFile)
	if err != nil {
		return err
	}

	portUUID, err := getPortUUID(ovsDriver, netconf.PrevResult.Interfaces)
	if err != nil {
		return fmt.Errorf("cannot get existing portUuid from db %v", err)
	}

	logger.Info("cmdAdd - interating all mirrors")
	for _, mirror := range netconf.Mirrors {

		logger.Infof("cmdAdd - calling CreateMirror %s", mirror.Name)
		err = ovsDriver.CreateMirror(netconf.BrName, mirror.Name)
		if err != nil {
			logger.Infof("cmdAdd - CreateMirror %s returned an error", mirror.Name)
			return fmt.Errorf("cannot create mirror %s: %v ", mirror.Name, err)
		}
		logger.Infof("cmdAdd - CreateMirror - success %s", mirror.Name)

		alreadyAttached, err := ovsDriver.IsMirrorConsumerAlreadyAttached(mirror.Name)
		if err != nil {
			logger.Infof("cmdAdd - IsMirrorConsumerAlreadyAttached %s returned an error", mirror.Name)
			return fmt.Errorf("cannot check if mirror %s has already an output port with error: %v ", mirror.Name, err)
		}
		if alreadyAttached {
			logger.Info("cmdAdd - IsMirrorConsumerAlreadyAttached, cannot continue")
			return fmt.Errorf("cannot attach port %s to mirror %s because there is already another port: %v", portUUID, mirror.Name, err)
		}

		logger.Infof("cmdAdd - attachPortToMirror - calling for mirror: %s", mirror.Name)
		if err = attachPortToMirror(ovsDriver, portUUID, mirror); err != nil {
			logger.Infof("cmdAdd - attachPortToMirror returned an error for mirror %s", mirror.Name)
			return fmt.Errorf("cannot attach port %s to mirror %s: %v", portUUID, mirror.Name, err)
		}
	}

	result := &current.Result{
		Interfaces: netconf.PrevResult.Interfaces,
	}

	logger.Infof("cmdAdd - result: %#v", result)
	return cnitypes.PrintResult(result, netconf.CNIVersion)
}

// cleanPorts removes all ports whose interfaces have an error.
func cleanPorts(ovsDriver *ovsdb.OvsBridgeDriver) error {
	ifaces, err := ovsDriver.FindInterfacesWithError()
	if err != nil {
		return fmt.Errorf("clean ports: %v", err)
	}
	for _, iface := range ifaces {
		log.Printf("Info: interface %s has error: removing corresponding port", iface)
		if err := ovsDriver.DeletePort(iface); err != nil {
			// Don't return an error here, just log its occurrence.
			// Something else may have removed the port already.
			log.Printf("Error: %v\n", err)
		}
	}
	return nil
}

// CmdDel remove handler for deleting container from network
func CmdDel(args *skel.CmdArgs) error {
	logCall("DEL", args)
	logger.Info("--------------CmdDel--------------")
	logger.Info(args.IfName)
	logger.Info(args.ContainerID)
	logger.Info(args.Netns)
	logger.Info(args.Args)
	logger.Info(args.Path)
	logger.Info(fmt.Sprintf("the config data: %s\n", args.StdinData))
	logger.Info("**********************************")

	netconf, err := config.LoadConf(args.StdinData)
	if err != nil {
		return err
	}
	logger.Infof("cmdDel - netconf parsed from StdinData is: %#v", netconf)

	ovsDriver, err := ovsdb.NewOvsBridgeDriver(netconf.BrName, netconf.SocketFile)
	if err != nil {
		return err
	}

	portUUID, err := getPortUUID(ovsDriver, netconf.PrevResult.Interfaces)
	if err != nil {
		return fmt.Errorf("cannot get existing portUuid from db %v", err)
	}

	logger.Info("cmdDel - interating all mirrors")
	for _, mirror := range netconf.Mirrors {

		mirrorExist, err := ovsDriver.IsMirrorPresent(mirror.Name)
		if err != nil {
			return err
		}
		if !mirrorExist {
			// skip error because CNI spec states that "Plugins should generally complete a DEL action without error even if some resources are missing"
			continue
		}

		if err = detachPortFromMirror(ovsDriver, portUUID, mirror); err != nil {
			logger.Infof("cmdDel - detachPortFromMirror returned an error for mirror %s", mirror.Name)
			return fmt.Errorf("cannot detach port %s from mirror %s: %v", portUUID, mirror.Name, err)
		}

		logger.Infof("cmdDel - calling DeleteMirror %s", mirror.Name)
		err = ovsDriver.DeleteMirror(netconf.BrName, mirror.Name)
		if err != nil {
			logger.Infof("cmdDel - DeleteMirror %s returned an error", mirror.Name)
			return fmt.Errorf("cannot create mirror %s: %v ", mirror.Name, err)
		}
		logger.Infof("cmdDel - DeleteMirror - success %s", mirror.Name)
	}

	logger.Info("cmdDel - calling cleanPorts")
	if err := cleanPorts(ovsDriver); err != nil {
		return err
	}

	result := &current.Result{
		Interfaces: netconf.PrevResult.Interfaces,
	}

	logger.Infof("cmdDel - result: %#v", result)
	return cnitypes.PrintResult(result, netconf.CNIVersion)
}

// CmdCheck check handler to make sure networking is as expected.
func CmdCheck(args *skel.CmdArgs) error {
	logCall("CHECK", args)

	logger.Info("--------------cmdCheck--------------")
	logger.Info(args.IfName)
	logger.Info(args.ContainerID)
	logger.Info(args.Netns)
	logger.Info(args.Args)
	logger.Info(args.Path)
	logger.Info(fmt.Sprintf("the config data: %s\n", args.StdinData))
	logger.Info("**********************************")

	netconf, err := config.LoadConf(args.StdinData)
	if err != nil {
		return err
	}

	ovsDriver, err := ovsdb.NewOvsBridgeDriver(netconf.BrName, netconf.SocketFile)
	if err != nil {
		return err
	}

	portUUID, err := getPortUUID(ovsDriver, netconf.PrevResult.Interfaces)
	if err != nil {
		return fmt.Errorf("cannot get existing portUuid from db %v", err)
	}

	for _, mirror := range netconf.Mirrors {

		mirrorExist, err := ovsDriver.CheckMirrorConsumerWithPorts(mirror.Name, portUUID)
		if err != nil {
			return err
		}

		if !mirrorExist {
			return fmt.Errorf("mirror %s not present", mirror.Name)
		}
	}

	return nil
}
