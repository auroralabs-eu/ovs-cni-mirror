// Modifications copyright (C) 2017 Che Wei, Lin
// Copyright 2014 Cisco Systems Inc. All rights reserved.
// Copyright 2019 Red Hat Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovsdb

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
)

const ovsPortOwner = "ovs-cni.network.kubevirt.io"
const (
	bridgeTable = "Bridge"
	ovsTable    = "Open_vSwitch"
)

var logger *zap.SugaredLogger

// Bridge defines an object in Bridge table
type Bridge struct {
	UUID string `ovsdb:"_uuid"`
}

// OpenvSwitch defines an object in Open_vSwitch table
type OpenvSwitch struct {
	UUID string `ovsdb:"_uuid"`
}

// OvsDriver OVS driver state
type OvsDriver struct {
	// OVS client
	ovsClient client.Client
}

// OvsBridgeDriver OVS bridge driver state
type OvsBridgeDriver struct {
	OvsDriver

	// Name of the OVS bridge
	OvsBridgeName string
}

func init() {
	logger = InitLogger("/home/master/ovs-logs/ovsdb.log")
	defer logger.Sync()
	logger.Info("Starting OVSDB....")
}

// connectToOvsDb connect to ovsdb
func connectToOvsDb(ovsSocket string) (client.Client, error) {
	dbmodel, err := model.NewDBModel("Open_vSwitch",
		map[string]model.Model{bridgeTable: &Bridge{}, ovsTable: &OpenvSwitch{}})
	if err != nil {
		return nil, fmt.Errorf("unable to create DB model error: %v", err)
	}

	ovsDB, err := client.NewOVSDBClient(dbmodel, client.WithEndpoint(ovsSocket))
	if err != nil {
		return nil, fmt.Errorf("unable to create DB client error: %v", err)
	}
	err = ovsDB.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ovsdb error: %v", err)
	}

	return ovsDB, nil
}

// NewOvsDriver Create a new OVS driver with Unix socket
func NewOvsDriver(ovsSocket string) (*OvsDriver, error) {
	ovsDriver := new(OvsDriver)

	ovsDB, err := connectToOvsDb(ovsSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ovsdb error: %v", err)
	}

	ovsDriver.ovsClient = ovsDB

	return ovsDriver, nil
}

// NewOvsBridgeDriver Create a new OVS driver for a bridge with Unix socket
func NewOvsBridgeDriver(bridgeName, socketFile string) (*OvsBridgeDriver, error) {
	ovsDriver := new(OvsBridgeDriver)

	if socketFile == "" {
		socketFile = "unix:/var/run/openvswitch/db.sock"
	}

	ovsDB, err := connectToOvsDb(socketFile)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ovsdb socket %s: error: %v", socketFile, err)
	}

	// Setup state
	ovsDriver.ovsClient = ovsDB
	ovsDriver.OvsBridgeName = bridgeName

	bridgeExist, err := ovsDriver.IsBridgePresent(bridgeName)
	if err != nil {
		return nil, err
	}

	if !bridgeExist {
		return nil, fmt.Errorf("failed to find bridge %s", bridgeName)
	}

	// Return the new OVS driver
	return ovsDriver, nil
}

// Wrapper for ovsDB transaction
func (ovsd *OvsDriver) ovsdbTransact(ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	// Perform OVSDB transaction
	reply, _ := ovsd.ovsClient.Transact(ops...)

	if len(reply) < len(ops) {
		return nil, errors.New("OVS transaction failed. Less replies than operations")
	}

	// Parse reply and look for errors
	for _, o := range reply {
		if o.Error != "" {
			return nil, errors.New("OVS Transaction failed err " + o.Error + " Details: " + o.Details)
		}
	}

	// Return success
	return reply, nil
}

// **************** OVS driver API ********************

func (ovsd *OvsBridgeDriver) CreateMirror(bridgeName, mirrorName string) error {
	mirrorExist, err := ovsd.IsMirrorPresent(mirrorName)
	if err != nil {
		return err
	}

	logger.Infof("CreateMirror - mirrorExist %t", mirrorExist)

	if !mirrorExist {
		mirrorUUID, mirrorOp := createMirrorOperation(mirrorName)

		logger.Infof("CreateMirror - mirrorUUID %#v", mirrorUUID)

		attachMirrorOp := attachMirrorOperation(mirrorUUID, bridgeName)

		// Perform OVS transaction
		operations := []ovsdb.Operation{*mirrorOp, *attachMirrorOp}

		logger.Infof("CreateMirror - operations %#v", operations)

		_, err = ovsd.ovsdbTransact(operations)
		return err
	}
	return nil
}

func (ovsd *OvsBridgeDriver) DeleteMirror(bridgeName, mirrorName string) error {
	logger.Info("DeleteMirror - called")
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	row, err := ovsd.findByCondition("Mirror", condition, nil)
	if err != nil {
		return err
	}
	logger.Infof("DeleteMirror - row: %#v", row)

	mirrorUUID := row["_uuid"].(ovsdb.UUID)
	logger.Infof("DeleteMirror - mirrorUUID %#v", mirrorUUID)

	selectSrcPorts := row["select_src_port"].(ovsdb.OvsSet).GoSet
	selectDstPorts := row["select_dst_port"].(ovsdb.OvsSet).GoSet

	// TODO workaround to handle output_port casting
	// - when output_port is empty in ovsdb, it returns an empty ovsdb.OvsSet
	// - when output_port contains an UUID reference, it returns a ovsdb.UUID
	// if isUUID = true => output_port is of type ovsdb.UUID, so it contains a UUID reference
	// otherwise => output_port is an empty ovsdb.OvsSet that cannot be casted to ovsdb.UUID
	outputPort, isUUID := row["output_port"].(ovsdb.UUID)

	logger.Infof("DeleteMirror - outputPort: %#v", outputPort)
	logger.Infof("DeleteMirror - selectSrcPorts %#v", selectSrcPorts)
	logger.Infof("DeleteMirror - selectDstPorts %#v", selectDstPorts)

	if len(selectSrcPorts) == 0 && len(selectDstPorts) == 0 && !isUUID {
		logger.Infof("DeleteMirror - mirror %s is empty - removing it", mirrorName)

		deleteOp := deleteMirrorOperation(mirrorName)
		detachFromBridgeOp := detachMirrorFromBridgeOperation(mirrorUUID, bridgeName)

		// Perform OVS transaction
		operations := []ovsdb.Operation{*deleteOp, *detachFromBridgeOp}

		logger.Infof("DeleteMirror - operations %#v", operations)

		_, err = ovsd.ovsdbTransact(operations)
		return err
	}

	return nil
}

func (ovsd *OvsBridgeDriver) AttachPortToMirror(portUUIDStr, mirrorName string, ingress, egress bool) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	if !ingress && !egress {
		return errors.New("a mirror must have either a ingress or an egress or both")
	}

	mutateMirrorOp := mutateMirrorOperation(portUUID, mirrorName, ingress, egress)

	logger.Infof("AttachPortToMirror - mutateMirrorOp: %#v", mutateMirrorOp)
	// Perform OVS transaction
	operations := []ovsdb.Operation{*mutateMirrorOp}

	_, err := ovsd.ovsdbTransact(operations)
	return err
}

func (ovsd *OvsBridgeDriver) DetachPortFromMirror(portUUIDStr, mirrorName string) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	mutateMirrorOp := detachPortFromMirrorOperation(portUUID, mirrorName)

	logger.Infof("AttachPortToMirror - mutateMirrorOp: %#v", mutateMirrorOp)
	// Perform OVS transaction
	operations := []ovsdb.Operation{*mutateMirrorOp}

	_, err := ovsd.ovsdbTransact(operations)
	return err
}

func (ovsd *OvsBridgeDriver) GetMirrorUUID(mirrorName string) (ovsdb.UUID, error) {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	row, err := ovsd.findByCondition("Mirror", condition, nil)
	if err != nil {
		return ovsdb.UUID{}, err
	}

	// We make a select transaction using the interface name
	// Then get the Mirror UUID from it
	mirrorUUID := row["_uuid"].(ovsdb.UUID)

	return mirrorUUID, nil
}

func (ovsd *OvsBridgeDriver) GetPortUUID(portName string) (ovsdb.UUID, error) {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, portName)
	row, err := ovsd.findByCondition("Port", condition, nil)
	if err != nil {
		return ovsdb.UUID{}, err
	}

	// We make a select transaction using the interface name
	// Then get the Port UUID from it
	portUUID := row["_uuid"].(ovsdb.UUID)

	return portUUID, nil
}

// IsMirrorPresent Check if the Mirror entry already exists
func (ovsd *OvsDriver) IsMirrorPresent(mirrorName string) (bool, error) {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	selectOp := []ovsdb.Operation{{
		Op:      "select",
		Table:   "Mirror",
		Where:   []ovsdb.Condition{condition},
		Columns: []string{"name"},
	}}

	transactionResult, err := ovsd.ovsdbTransact(selectOp)
	if err != nil {
		return false, err
	}

	if len(transactionResult) != 1 {
		// there is no need to return an error, because we want to create
		// a new mirror if not exists
		return false, nil
	}

	operationResult := transactionResult[0]
	if operationResult.Error != "" {
		return false, fmt.Errorf("%s - %s", operationResult.Error, operationResult.Details)
	}

	if len(operationResult.Rows) != 1 {
		return false, nil
	}

	return true, nil
}

// IsBridgePresent Check if the bridge entry already exists
func (ovsd *OvsDriver) IsBridgePresent(bridgeName string) (bool, error) {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, bridgeName)
	selectOp := []ovsdb.Operation{{
		Op:      "select",
		Table:   "Bridge",
		Where:   []ovsdb.Condition{condition},
		Columns: []string{"name"},
	}}

	transactionResult, err := ovsd.ovsdbTransact(selectOp)
	if err != nil {
		return false, err
	}

	if len(transactionResult) != 1 {
		return false, fmt.Errorf("unknow error")
	}

	operationResult := transactionResult[0]
	if operationResult.Error != "" {
		return false, fmt.Errorf("%s - %s", operationResult.Error, operationResult.Details)
	}

	if len(operationResult.Rows) != 1 {
		return false, nil
	}

	return true, nil
}

// ************************ Notification handler for OVS DB changes ****************

// Update yet to be implemented
func (ovsd *OvsDriver) Update(context interface{}, tableUpdates ovsdb.TableUpdates) {
}

// Disconnected yet to be implemented
func (ovsd *OvsDriver) Disconnected(ovsClient client.Client) {
}

// Locked yet to be implemented
func (ovsd *OvsDriver) Locked([]interface{}) {
}

// Stolen yet to be implemented
func (ovsd *OvsDriver) Stolen([]interface{}) {
}

// Echo yet to be implemented
func (ovsd *OvsDriver) Echo([]interface{}) {
}

// ************************ Helper functions ********************
func (ovsd *OvsDriver) findByCondition(table string, condition ovsdb.Condition, columns []string) (map[string]interface{}, error) {
	selectOp := ovsdb.Operation{
		Op:    "select",
		Table: table,
		Where: []ovsdb.Condition{condition},
	}

	if columns != nil {
		selectOp.Columns = columns
	}

	transactionResult, err := ovsd.ovsdbTransact([]ovsdb.Operation{selectOp})
	if err != nil {
		return nil, err
	}

	if len(transactionResult) != 1 {
		return nil, fmt.Errorf("unknown error")
	}

	operationResult := transactionResult[0]
	if operationResult.Error != "" {
		return nil, fmt.Errorf("%s - %s", operationResult.Error, operationResult.Details)
	}

	if len(operationResult.Rows) != 1 {
		return nil, fmt.Errorf("failed to find object from table %s", table)
	}

	return operationResult.Rows[0], nil
}

func createMirrorOperation(mirrorName string) (ovsdb.UUID, *ovsdb.Operation) {
	mirrorUUIDStr := mirrorName
	mirrorUUID := ovsdb.UUID{GoUUID: mirrorUUIDStr}

	logger.Infof("cmdAdd - createMirrorOperation() - mirrorUUID: %#v", mirrorUUID)

	mirror := make(map[string]interface{})
	mirror["name"] = mirrorName
	logger.Infof("cmdAdd - createMirrorOperation() - mirror: %#v", mirror)

	logger.Infof("cmdAdd - createMirrorOperation() - mirrorUUIDStr: " + mirrorUUIDStr)

	// Add an entry in Port table
	mirrorOp := ovsdb.Operation{
		Op:       "insert",
		Table:    "Mirror",
		Row:      mirror,
		UUIDName: mirrorUUIDStr,
	}
	logger.Infof("cmdAdd - createMirrorOperation() - mirrorUUIDStr: %#v", mirrorUUIDStr)
	logger.Infof("cmdAdd - createMirrorOperation() - mirrorUUID: %#v", mirrorUUID)
	logger.Infof("cmdAdd - createMirrorOperation() - mirrorOp: %#v", mirrorOp)

	return mirrorUUID, &mirrorOp
}

func mutateMirrorOperation(portUUID ovsdb.UUID, mirrorName string, ingress, egress bool) *ovsdb.Operation {
	// mutate the Ingress and Egress columns of the row in the Mirror table
	mutateSet, _ := ovsdb.NewOvsSet(portUUID)
	var mutations []ovsdb.Mutation = []ovsdb.Mutation{}
	if ingress {
		// select_src_port = Ports on which arriving packets are selected for mirroring
		mutationIngress := ovsdb.NewMutation("select_src_port", ovsdb.MutateOperationInsert, mutateSet)
		mutations = append(mutations, *mutationIngress)
	}
	if egress {
		// select_dst_port = Ports on which departing packets are selected for mirroring
		mutationEgress := ovsdb.NewMutation("select_dst_port", ovsdb.MutateOperationInsert, mutateSet)
		mutations = append(mutations, *mutationEgress)
	}

	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Mirror",
		Mutations: mutations,
		Where:     []ovsdb.Condition{condition},
	}
	logger.Infof("cmdAdd - CreateMirrorPort() - mutateMirrorOperation mutateOp: %#v", mutateOp)

	return &mutateOp
}

func attachMirrorOperation(mirrorUUID ovsdb.UUID, bridgeName string) *ovsdb.Operation {
	// mutate the Mirrors column of the row in the Bridge table
	mutateSet, _ := ovsdb.NewOvsSet(mirrorUUID)
	mutation := ovsdb.NewMutation("mirrors", ovsdb.MutateOperationInsert, mutateSet)
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, bridgeName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []ovsdb.Mutation{*mutation},
		Where:     []ovsdb.Condition{condition},
	}
	logger.Infof("cmdAdd - attachMirrorOperation mutateOp: %#v", mutateOp)

	return &mutateOp
}

func detachPortFromMirrorOperation(portUUID ovsdb.UUID, mirrorName string) *ovsdb.Operation {
	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := ovsdb.NewOvsSet(portUUID)
	// select_src_port = Ports on which arriving packets are selected for mirroring
	mutationIngress := ovsdb.NewMutation("select_src_port", ovsdb.MutateOperationDelete, mutateSet)
	// select_dst_port = Ports on which departing packets are selected for mirroring
	mutationEgress := ovsdb.NewMutation("select_dst_port", ovsdb.MutateOperationDelete, mutateSet)
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Mirror",
		Mutations: []ovsdb.Mutation{*mutationIngress, *mutationEgress},
		Where:     []ovsdb.Condition{condition},
	}

	return &mutateOp
}

func deleteMirrorOperation(mirrorName string) *ovsdb.Operation {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	mirrorOp := ovsdb.Operation{
		Op:    "delete",
		Table: "Mirror",
		Where: []ovsdb.Condition{condition},
	}

	return &mirrorOp
}

func detachMirrorFromBridgeOperation(mirrorUUID ovsdb.UUID, bridgeName string) *ovsdb.Operation {
	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := ovsdb.NewOvsSet(mirrorUUID)
	mutation := ovsdb.NewMutation("mirrors", ovsdb.MutateOperationDelete, mutateSet)
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, bridgeName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []ovsdb.Mutation{*mutation},
		Where:     []ovsdb.Condition{condition},
	}

	return &mutateOp
}
