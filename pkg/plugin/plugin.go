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
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/ovsdb"
	"github.com/k8snetworkplumbingwg/ovs-cni/pkg/types"
)

var logger *zap.SugaredLogger

const macSetupRetries = 2

// EnvArgs args containing common, desired mac and ovs port name
type EnvArgs struct {
	cnitypes.CommonArgs
	MAC     cnitypes.UnmarshallableString `json:"mac,omitempty"`
	OvnPort cnitypes.UnmarshallableString `json:"ovnPort,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	logger = InitLogger("/home/master/ovs-logs/producer.log")
	defer logger.Sync()
	logger.Info("Starting PLUGIN....")
}

func logCall(command string, args *skel.CmdArgs) {
	log.Printf("CNI %s was called for container ID: %s, network namespace %s, interface name %s, configuration: %s",
		command, args.ContainerID, args.Netns, args.IfName, string(args.StdinData[:]))
}

func getEnvArgs(envArgsString string) (*EnvArgs, error) {
	if envArgsString != "" {
		e := EnvArgs{}
		err := cnitypes.LoadArgs(envArgsString, &e)
		if err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, nil
}

func getBridgeName(bridgeName, ovnPort string) (string, error) {
	if bridgeName != "" {
		return bridgeName, nil
	} else if bridgeName == "" && ovnPort != "" {
		return "br-int", nil
	}

	return "", fmt.Errorf("failed to get bridge name")
}

func getPortUUID(ovsDriver *ovsdb.OvsBridgeDriver, interfaces []*current.Interface) (string, error) {
	logger.Infof("cmdAdd - getPort() - ovsDriver: %#v", ovsDriver)
	logger.Infof("cmdAdd - getPort() - interfaces: %#v", interfaces)

	for _, iface := range interfaces {
		uuid, err := ovsDriver.GetPortUUID(iface.Name)
		logger.Infof("cmdAdd - getPortUUID() - iterating on interface: %#v", iface)
		logger.Infof("cmdAdd - getPortUUID() - iterating - uuid: %#v", uuid)
		logger.Infof("cmdAdd - getPortUUID() - iterating - err: %#v", err)
		if err == nil {
			return uuid.GoUUID, nil
		} else {
			logger.Infof("cmdAdd - getPortUUID() - port with name %s not found in db", iface.Name)
		}
	}

	return "", errors.New("Cannot find port in db")
}

func attachPortToMirror(ovsDriver *ovsdb.OvsBridgeDriver, portUUIDStr string, mirror *types.Mirror) error {
	logger.Infof("attachPortToMirror - called")

	err := ovsDriver.AttachPortToMirror(portUUIDStr, mirror.Name, mirror.Ingress, mirror.Egress)
	if err != nil {
		logger.Info("attachPortToMirror - AttachPortToMirror ERROR")
		return err
	}
	logger.Infof("attachPortToMirror - AttachPortToMirror - DONE")

	return nil
}

// func splitVlanIds(trunks []*types.Trunk) ([]uint, error) {
// 	vlans := make(map[uint]bool)
// 	for _, item := range trunks {
// 		var minID uint = 0
// 		var maxID uint = 0
// 		if item.MinID != nil {
// 			minID = *item.MinID
// 			if minID < 0 || minID > 4096 {
// 				return nil, errors.New("incorrect trunk minID parameter")
// 			}
// 		}
// 		if item.MaxID != nil {
// 			maxID = *item.MaxID
// 			if maxID < 0 || maxID > 4096 {
// 				return nil, errors.New("incorrect trunk maxID parameter")
// 			}
// 			if maxID < minID {
// 				return nil, errors.New("minID is greater than maxID in trunk parameter")
// 			}
// 		}
// 		if minID > 0 && maxID > 0 {
// 			for v := minID; v <= maxID; v++ {
// 				vlans[v] = true
// 			}
// 		}
// 		var id uint = 0
// 		if item.ID != nil {
// 			id = *item.ID
// 			if id < 0 || minID > 4096 {
// 				return nil, errors.New("incorrect trunk id parameter")
// 			}
// 			vlans[id] = true
// 		}
// 	}
// 	if len(vlans) == 0 {
// 		return nil, errors.New("trunk parameter is misconfigured")
// 	}
// 	vlanIds := make([]uint, 0, len(vlans))
// 	for k := range vlans {
// 		vlanIds = append(vlanIds, k)
// 	}
// 	sort.Slice(vlanIds, func(i, j int) bool { return vlanIds[i] < vlanIds[j] })
// 	return vlanIds, nil
// }

// CmdAdd add handler for attaching container into network
func CmdAdd(args *skel.CmdArgs) error {
	logCall("ADD", args)
	logger.Info("--------------cmdAdd--------------")
	logger.Info(args.IfName) // ovstest
	logger.Info(args.ContainerID)
	logger.Info(args.Netns)                                           // format is /var/run/netns/cni-<ID>
	logger.Info(args.Args)                                            // "IgnoreUnknown=true;K8S_POD_NAMESPACE=emu-cni;K8S_POD_NAME=ovs-client-9-7b6775d6c9-lw9ck;K8S_POD_INFRA_CONTAINER_ID=<args.ContainerID>;K8S_POD_UID=<POD UID????>"
	logger.Info(args.Path)                                            // /opt/cni/bin:/var/lib/rancher/k3s/data/<args.ContainerID>/bin
	logger.Info(fmt.Sprintf("the config data: %s\n", args.StdinData)) // value from NAD config

	// {"level":"info","ts":1649942843.6303148,"caller":"plugin/plugin.go:262","msg":"the config data: {\"bridge\":\"br-emu-cni\",\"cniVersion\":\"0.4.0\",\"mirrors\":[{\"egress\":true,\"ingress\":true,\"name\":\"mirror-1\"}],\"name\":\"nad-al-cni-1\",
	// \"prevResult\":{\"cniVersion\":\"0.4.0\",\"interfaces\":[{\"name\":\"veth66be9a38\",\"mac\":\"1a:59:e8:9b:ff:59\"},{\"name\":\"net1\",\"mac\":\"82:01:de:fb:0e:0d\",\"sandbox\":\"/var/run/netns/cni-3c569fd6-b4a0-eaab-6abf-e5f3d75ba84a\"}],\"dns\":{}},\"type\":\"ovs-cni-mirror-producer\"}\n"}

	// envArgs, err := getEnvArgs(args.Args)
	// if err != nil {
	// 	return err
	// }

	// var mac string
	// var ovnPort string
	// if envArgs != nil {
	// 	mac = string(envArgs.MAC)
	// 	ovnPort = string(envArgs.OvnPort)
	// }

	netconf, err := config.LoadConf(args.StdinData)
	if err != nil {
		return err
	}
	logger.Infof("cmdAdd - netconf parsed from StdinData is: %#v", netconf)

	// bridgeName, err := getBridgeName(netconf.BrName, ovnPort)
	// if err != nil {
	// 	return err
	// }
	// logger.Infof("cmdAdd - bridgeName: %#v", bridgeName)

	ovsDriver, err := ovsdb.NewOvsBridgeDriver(netconf.BrName, netconf.SocketFile)
	if err != nil {
		return err
	}

	contNetns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer contNetns.Close()

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

// func getOvsPortForContIface(ovsDriver *ovsdb.OvsBridgeDriver, contIface string, contNetnsPath string) (string, bool, error) {
// 	// External IDs were set on the port during ADD call.
// 	return ovsDriver.GetOvsPortForContIface(contIface, contNetnsPath)
// }

// cleanPorts removes all ports whose interfaces have an error.
// func cleanPorts(ovsDriver *ovsdb.OvsBridgeDriver) error {
// 	ifaces, err := ovsDriver.FindInterfacesWithError()
// 	if err != nil {
// 		return fmt.Errorf("clean ports: %v", err)
// 	}
// 	for _, iface := range ifaces {
// 		log.Printf("Info: interface %s has error: removing corresponding port", iface)
// 		if err := ovsDriver.DeletePort(iface); err != nil {
// 			// Don't return an error here, just log its occurrence.
// 			// Something else may have removed the port already.
// 			log.Printf("Error: %v\n", err)
// 		}
// 	}
// 	return nil
// }

// func removeOvsPort(ovsDriver *ovsdb.OvsBridgeDriver, portName string) error {

// 	return ovsDriver.DeletePort(portName)
// }

// CmdDel remove handler for deleting container from network
func CmdDel(args *skel.CmdArgs) error {
	logCall("DEL", args)
	logger.Info("--------------CmdDel--------------")
	// logger.Info(args.IfName)
	// logger.Info(args.ContainerID)
	// logger.Info(args.Netns)                                           // format is /var/run/netns/cni-<ID>
	// logger.Info(args.Args)                                            // "IgnoreUnknown=true;K8S_POD_NAMESPACE=emu-cni;K8S_POD_NAME=ovs-client-9-7b6775d6c9-lw9ck;K8S_POD_INFRA_CONTAINER_ID=<args.ContainerID>;K8S_POD_UID=<POD UID????>"
	// logger.Info(args.Path)                                            // /opt/cni/bin:/var/lib/rancher/k3s/data/<args.ContainerID>/bin
	// logger.Info(fmt.Sprintf("the config data: %s\n", args.StdinData)) // value from NAD config

	//cRef := config.GetCRef(args.ContainerID, args.IfName)
	//cache, err := config.LoadConfFromCache(cRef)
	//if err != nil {
	//	// If cmdDel() fails, cached netconf is cleaned up by
	//	// the followed defer call. However, subsequence calls
	//	// of cmdDel() from kubelet fail in a dead loop due to
	//	// cached netconf doesn't exist.
	//	// Return nil when loadConfFromCache fails since the rest
	//	// of cmdDel() code relies on netconf as input argument
	//	// and there is no meaning to continue.
	//	return nil
	//}
	//
	//defer func() {
	//	if err == nil {
	//		utils.CleanCache(cRef)
	//	}
	//}()
	//
	//envArgs, err := getEnvArgs(args.Args)
	//if err != nil {
	//	return err
	//}
	//
	//var ovnPort string
	//if envArgs != nil {
	//	ovnPort = string(envArgs.OvnPort)
	//}
	//
	//bridgeName, err := getBridgeName(cache.Netconf.BrName, ovnPort)
	//if err != nil {
	//	return err
	//}
	//
	//ovsDriver, err := ovsdb.NewOvsBridgeDriver(bridgeName, cache.Netconf.SocketFile)
	//if err != nil {
	//	return err
	//}
	//
	//if cache.Netconf.IPAM.Type != "" {
	//	err = ipam.ExecDel(cache.Netconf.IPAM.Type, args.StdinData)
	//	if err != nil {
	//		return err
	//	}
	//}
	//
	//if args.Netns == "" {
	//	// The CNI_NETNS parameter may be empty according to version 0.4.0
	//	// of the CNI spec (https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md).
	//	if sriov.IsOvsHardwareOffloadEnabled(cache.Netconf.DeviceID) {
	//		// SR-IOV Case - The sriov device is moved into host network namespace when args.Netns is empty.
	//		// This happens container is killed due to an error (example: CrashLoopBackOff, OOMKilled)
	//		var rep string
	//		if rep, err = sriov.GetNetRepresentor(cache.Netconf.DeviceID); err != nil {
	//			return err
	//		}
	//		if err = removeOvsPort(ovsDriver, rep); err != nil {
	//			// Don't throw err as delete can be called multiple times because of error in ResetVF and ovs
	//			// port is already deleted in a previous invocation.
	//			log.Printf("Error: %v\n", err)
	//		}
	//		if err = sriov.ResetVF(args, cache.Netconf.DeviceID, cache.OrigIfName); err != nil {
	//			return err
	//		}
	//	} else {
	//		// In accordance with the spec we clean up as many resources as possible.
	//		if err := cleanPorts(ovsDriver); err != nil {
	//			return err
	//		}
	//	}
	//	return nil
	//}
	//
	//// Unlike veth pair, OVS port will not be automatically removed when
	//// container namespace is gone. Find port matching DEL arguments and remove
	//// it explicitly.
	//portName, portFound, err := getOvsPortForContIface(ovsDriver, args.IfName, args.Netns)
	//if err != nil {
	//	return fmt.Errorf("Failed to obtain OVS port for given connection: %v", err)
	//}
	//
	//// Do not return an error if the port was not found, it may have been
	//// already removed by someone.
	//if portFound {
	//	if err := removeOvsPort(ovsDriver, portName); err != nil {
	//		return err
	//	}
	//}
	//
	//if sriov.IsOvsHardwareOffloadEnabled(cache.Netconf.DeviceID) {
	//	err = sriov.ReleaseVF(args, cache.OrigIfName)
	//	if err != nil {
	//		// try to reset vf into original state as much as possible in case of error
	//		sriov.ResetVF(args, cache.Netconf.DeviceID, cache.OrigIfName)
	//	}
	//} else {
	//	err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
	//		err = ip.DelLinkByName(args.IfName)
	//		if err != nil {
	//			// clean up as many stale ovs resources as possible.
	//			cleanPorts(ovsDriver)
	//		}
	//		return err
	//	})
	//	// do the following as per cni spec (i.e. Plugins should generally complete a DEL action
	//	// without error even if some resources are missing)
	//	if _, ok := err.(ns.NSPathNotExistErr); ok || err == ip.ErrLinkNotFound {
	//		if portFound {
	//			ip.DelLinkByName(portName)
	//		}
	//		cleanPorts(ovsDriver)
	//		return nil
	//	}
	//}
	//
	//return err
	return nil
}

// CmdCheck check handler to make sure networking is as expected.
func CmdCheck(args *skel.CmdArgs) error {
	logCall("CHECK", args)

	logger.Info("--------------cmdCheck--------------")
	// logger.Info(args.IfName)
	// logger.Info(args.ContainerID)
	// logger.Info(args.Netns)
	// logger.Info(args.Args)
	// logger.Info(args.Path)
	// logger.Info(fmt.Sprintf("cmdCheck - the config data: %s\n", args.StdinData))

	//netconf, err := config.LoadConf(args.StdinData)
	//if err != nil {
	//	return err
	//}
	//
	//// run the IPAM plugin
	//if netconf.NetConf.IPAM.Type != "" {
	//	err = ipam.ExecCheck(netconf.NetConf.IPAM.Type, args.StdinData)
	//	if err != nil {
	//		return fmt.Errorf("failed to check with IPAM plugin type %q: %v", netconf.NetConf.IPAM.Type, err)
	//	}
	//}
	//
	//// check cache
	//cRef := config.GetCRef(args.ContainerID, args.IfName)
	//cache, err := config.LoadConfFromCache(cRef)
	//if err != nil {
	//	return err
	//}
	//if err := validateCache(cache, netconf); err != nil {
	//	return err
	//}
	//
	//// Parse previous result.
	//if netconf.NetConf.RawPrevResult == nil {
	//	return fmt.Errorf("Required prevResult missing")
	//}
	//if err := version.ParsePrevResult(&netconf.NetConf); err != nil {
	//	return err
	//}
	//result, err := current.NewResultFromResult(netconf.NetConf.PrevResult)
	//if err != nil {
	//	return err
	//}
	//
	//var contIntf, hostIntf current.Interface
	//// Find interfaces
	//for _, intf := range result.Interfaces {
	//	if args.IfName == intf.Name {
	//		if args.Netns == intf.Sandbox {
	//			contIntf = *intf
	//		}
	//	} else {
	//		// Check prevResults for ips against values found in the host
	//		if err := validateInterface(*intf, true); err != nil {
	//			return err
	//		}
	//		hostIntf = *intf
	//	}
	//}
	//
	//// The namespace must be the same as what was configured
	//if args.Netns != contIntf.Sandbox {
	//	return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
	//		contIntf.Sandbox, args.Netns)
	//}
	//
	//netns, err := ns.GetNS(args.Netns)
	//if err != nil {
	//	return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	//}
	//defer netns.Close()
	//
	//// Check prevResults for ips and routes against values found in the container
	//if err := netns.Do(func(_ ns.NetNS) error {
	//
	//	// Check interface against values found in the container
	//	err := validateInterface(contIntf, false)
	//	if err != nil {
	//		return err
	//	}
	//
	//	err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
	//	if err != nil {
	//		return err
	//	}
	//
	//	err = ip.ValidateExpectedRoute(result.Routes)
	//	if err != nil {
	//		return err
	//	}
	//	return nil
	//}); err != nil {
	//	return err
	//}
	//
	//// ovs specific check
	//if err := validateOvs(args, netconf, hostIntf.Name); err != nil {
	//	return err
	//}

	return nil
}

// func validateCache(cache *types.CachedNetConf, netconf *types.NetConf) error {
// 	if cache.Netconf.BrName != netconf.BrName {
// 		return fmt.Errorf("BrName mismatch. cache=%s,netconf=%s",
// 			cache.Netconf.BrName, netconf.BrName)
// 	}

// 	if cache.Netconf.SocketFile != netconf.SocketFile {
// 		return fmt.Errorf("SocketFile mismatch. cache=%s,netconf=%s",
// 			cache.Netconf.SocketFile, netconf.SocketFile)
// 	}

// 	if cache.Netconf.IPAM.Type != netconf.IPAM.Type {
// 		return fmt.Errorf("IPAM mismatch. cache=%s,netconf=%s",
// 			cache.Netconf.IPAM.Type, netconf.IPAM.Type)
// 	}

// 	if cache.Netconf.DeviceID != netconf.DeviceID {
// 		return fmt.Errorf("DeviceID mismatch. cache=%s,netconf=%s",
// 			cache.Netconf.DeviceID, netconf.DeviceID)
// 	}

// 	return nil
// }

// func validateInterface(intf current.Interface, isHost bool) error {
// 	var link netlink.Link
// 	var err error
// 	var iftype string
// 	if isHost {
// 		iftype = "Host"
// 	} else {
// 		iftype = "Container"
// 	}

// 	if intf.Name == "" {
// 		return fmt.Errorf("%s interface name missing in prevResult: %v", iftype, intf.Name)
// 	}
// 	link, err = netlink.LinkByName(intf.Name)
// 	if err != nil {
// 		return fmt.Errorf("Error: %s Interface name in prevResult: %s not found", iftype, intf.Name)
// 	}
// 	if !isHost && intf.Sandbox == "" {
// 		return fmt.Errorf("Error: %s interface %s should not be in host namespace", iftype, link.Attrs().Name)
// 	}

// 	_, isVeth := link.(*netlink.Veth)
// 	if !isVeth {
// 		return fmt.Errorf("Error: %s interface %s not of type veth/p2p", iftype, link.Attrs().Name)
// 	}

// 	if intf.Mac != "" && intf.Mac != link.Attrs().HardwareAddr.String() {
// 		return fmt.Errorf("Error: Interface %s Mac %s doesn't match %s Mac: %s", intf.Name, intf.Mac, iftype, link.Attrs().HardwareAddr)
// 	}

// 	return nil
// }

// func validateOvs(args *skel.CmdArgs, netconf *types.NetConf, hostIfname string) error {
// 	envArgs, err := getEnvArgs(args.Args)
// 	if err != nil {
// 		return err
// 	}
// 	var ovnPort string
// 	if envArgs != nil {
// 		ovnPort = string(envArgs.OvnPort)
// 	}

// 	bridgeName, err := getBridgeName(netconf.BrName, ovnPort)
// 	if err != nil {
// 		return err
// 	}

// 	ovsDriver, err := ovsdb.NewOvsBridgeDriver(bridgeName, netconf.SocketFile)
// 	if err != nil {
// 		return err
// 	}

// 	found, err := ovsDriver.IsBridgePresent(netconf.BrName)
// 	if err != nil {
// 		return err
// 	}
// 	if !found {
// 		return fmt.Errorf("Error: bridge %s is not found in OVS", netconf.BrName)
// 	}

// 	ifaces, err := ovsDriver.FindInterfacesWithError()
// 	if err != nil {
// 		return err
// 	}
// 	if len(ifaces) > 0 {
// 		return fmt.Errorf("Error: There are some interfaces in error state: %v", ifaces)
// 	}

// 	vlanMode, tag, trunk, err := ovsDriver.GetOFPortVlanState(hostIfname)
// 	if err != nil {
// 		return fmt.Errorf("Error: Failed to retrieve port %s state: %v", hostIfname, err)
// 	}

// 	// check vlan tag
// 	if netconf.VlanTag == nil {
// 		if tag != nil {
// 			return fmt.Errorf("vlan tag mismatch. ovs=%d,netconf=nil", *tag)
// 		}
// 	} else {
// 		if tag == nil {
// 			return fmt.Errorf("vlan tag mismatch. ovs=nil,netconf=%d", *netconf.VlanTag)
// 		}
// 		if *tag != *netconf.VlanTag {
// 			return fmt.Errorf("vlan tag mismatch. ovs=%d,netconf=%d", *tag, *netconf.VlanTag)
// 		}
// 		if vlanMode != "access" {
// 			return fmt.Errorf("vlan mode mismatch. expected=access,real=%s", vlanMode)
// 		}
// 	}

// 	// check trunk
// 	netconfTrunks := make([]uint, 0)
// 	if len(netconf.Trunk) > 0 {
// 		trunkVlanIds, err := splitVlanIds(netconf.Trunk)
// 		if err != nil {
// 			return err
// 		}
// 		netconfTrunks = append(netconfTrunks, trunkVlanIds...)
// 	}
// 	if len(trunk) != len(netconfTrunks) {
// 		return fmt.Errorf("trunk mismatch. ovs=%v,netconf=%v", trunk, netconfTrunks)
// 	}
// 	if len(netconfTrunks) > 0 {
// 		for i := 0; i < len(trunk); i++ {
// 			if trunk[i] != netconfTrunks[i] {
// 				return fmt.Errorf("trunk mismatch. ovs=%v,netconf=%v", trunk, netconfTrunks)
// 			}
// 		}

// 		if vlanMode != "trunk" {
// 			return fmt.Errorf("vlan mode mismatch. expected=trunk,real=%s", vlanMode)
// 		}
// 	}

// 	return nil
// }
