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
	"log"
	"reflect"

	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
)

const ovsPortOwner = "ovs-cni.network.kubevirt.io"
const (
	bridgeTable = "Bridge"
	ovsTable    = "Open_vSwitch"
)

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

const (
	MirrorProducer = iota
	MirrorConsumer
)

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

// DeletePort Delete a port from OVS
func (ovsd *OvsBridgeDriver) DeletePort(intfName string) error {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, intfName)
	row, err := ovsd.findByCondition("Port", condition, nil)
	if err != nil {
		return err
	}

	externalIDs, err := getExternalIDs(row)
	if err != nil {
		return fmt.Errorf("get external ids: %v", err)
	}
	if externalIDs["owner"] != ovsPortOwner {
		return fmt.Errorf("port not created by ovs-cni")
	}

	// We make a select transaction using the interface name
	// Then get the Port UUID from it
	portUUID := row["_uuid"].(ovsdb.UUID)

	intfOp := deleteInterfaceOperation(intfName)

	portOp := deletePortOperation(intfName)

	mutateOp := detachPortOperation(portUUID, ovsd.OvsBridgeName)

	// Perform OVS transaction
	operations := []ovsdb.Operation{*intfOp, *portOp, *mutateOp}

	_, err = ovsd.ovsdbTransact(operations)
	return err
}

func getExternalIDs(row map[string]interface{}) (map[string]string, error) {
	rowVal, ok := row["external_ids"]
	if !ok {
		return nil, fmt.Errorf("row does not contain external_ids")
	}

	rowValOvsMap, ok := rowVal.(ovsdb.OvsMap)
	if !ok {
		return nil, fmt.Errorf("not a OvsMap: %T: %v", rowVal, rowVal)
	}

	extIDs := make(map[string]string, len(rowValOvsMap.GoMap))
	for key, value := range rowValOvsMap.GoMap {
		extIDs[key.(string)] = value.(string)
	}
	return extIDs, nil
}

func (ovsd *OvsBridgeDriver) CreateMirror(bridgeName, mirrorName string) error {
	mirrorExist, err := ovsd.IsMirrorPresent(mirrorName)
	if err != nil {
		return err
	}

	if !mirrorExist {
		mirrorUUID, mirrorOp := createMirrorOperation(mirrorName)

		attachMirrorOp := attachMirrorOperation(mirrorUUID, bridgeName)

		// Perform OVS transaction
		operations := []ovsdb.Operation{*mirrorOp, *attachMirrorOp}

		_, err = ovsd.ovsdbTransact(operations)
		return err
	}
	return nil
}

func (ovsd *OvsBridgeDriver) DeleteMirror(bridgeName, mirrorName string) error {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	row, err := ovsd.findByCondition("Mirror", condition, nil)
	if err != nil {
		return err
	}

	mirrorUUID := row["_uuid"].(ovsdb.UUID)

	// Workaround to check output_port, select_dst_port and select_src_port consistenly, processing all
	// of them as array of UUIDs.
	// This is useful because ovn-org/libovsdb:
	// - when row["column"] is empty in ovsdb, it returns an empty ovsdb.OvsSet
	// - when row["column"] contains an UUID reference, it returns a ovsdb.UUID (not ovsdb.OvsSet)
	// - when row["column"] contains multiple UUID references, it returns an ovsdb.OvsSet with the elements
	selectSrcPorts, err := convertToArray(row["select_src_port"])
	if err != nil {
		return fmt.Errorf("cannot convert select_src_port to an array error: %v", err)
	}
	selectDstPorts, err := convertToArray(row["select_dst_port"])
	if err != nil {
		return fmt.Errorf("cannot convert select_dst_port to an array error: %v", err)
	}
	outputPorts, err := convertToArray(row["output_port"])
	if err != nil {
		return fmt.Errorf("cannot convert output_port to an array error: %v", err)
	}

	if len(selectSrcPorts) == 0 && len(selectDstPorts) == 0 && len(outputPorts) == 0 {
		deleteOp := deleteMirrorOperation(mirrorName)
		detachFromBridgeOp := detachMirrorFromBridgeOperation(mirrorUUID, bridgeName)

		// Perform OVS transaction
		operations := []ovsdb.Operation{*deleteOp, *detachFromBridgeOp}

		_, err = ovsd.ovsdbTransact(operations)
		return err
	}

	return nil
}

func (ovsd *OvsBridgeDriver) AttachPortToMirrorProducer(portUUIDStr, mirrorName string, ingress, egress bool) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	if !ingress && !egress {
		return errors.New("a mirror producer must have either a ingress or an egress or both")
	}

	attachPortMirrorOp := attachPortToMirrorProducerOperation(portUUID, mirrorName, ingress, egress)

	// Perform OVS transaction
	operations := []ovsdb.Operation{*attachPortMirrorOp}

	_, err := ovsd.ovsdbTransact(operations)
	return err
}

func (ovsd *OvsBridgeDriver) AttachPortToMirrorConsumer(portUUIDStr, mirrorName string) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	attachPortMirrorOp := attachPortToMirrorConsumerOperation(portUUID, mirrorName)

	// Perform OVS transaction
	operations := []ovsdb.Operation{*attachPortMirrorOp}

	_, err := ovsd.ovsdbTransact(operations)
	return err
}

func (ovsd *OvsBridgeDriver) DetachPortFromMirrorProducer(portUUIDStr, mirrorName string) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	mutateMirrorOp := detachPortFromMirrorOperation(portUUID, mirrorName, MirrorProducer)

	// Perform OVS transaction
	operations := []ovsdb.Operation{*mutateMirrorOp}

	_, err := ovsd.ovsdbTransact(operations)
	return err
}

func (ovsd *OvsBridgeDriver) DetachPortFromMirrorConsumer(portUUIDStr, mirrorName string) error {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	mutateMirrorOp := detachPortFromMirrorOperation(portUUID, mirrorName, MirrorConsumer)

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

func (ovsd *OvsDriver) IsMirrorConsumerAlreadyAttached(mirrorName string) (bool, error) {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	row, err := ovsd.findByCondition("Mirror", condition, nil)
	if err != nil {
		return false, err
	}

	outputPorts, err := convertToArray(row["output_port"])
	if err != nil {
		return false, fmt.Errorf("cannot convert output_port to an array error: %v", err)
	}

	if len(outputPorts) == 0 {
		return false, nil
	}
	return true, nil
}

func (ovsd *OvsDriver) CheckMirrorProducerWithPorts(mirrorName string, ingress, egress bool, portUUIDStr string) (bool, error) {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	var conditions []ovsdb.Condition = []ovsdb.Condition{}
	conditionName := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	conditions = append(conditions, conditionName)
	if ingress {
		// select_src_port = Ports on which arriving packets are selected for mirroring
		conditionIngress := ovsdb.NewCondition("select_src_port", ovsdb.ConditionIncludes, portUUID)
		conditions = append(conditions, conditionIngress)
	}
	if egress {
		// select_dst_port = Ports on which departing packets are selected for mirroring
		conditionsEgress := ovsdb.NewCondition("select_dst_port", ovsdb.ConditionIncludes, portUUID)
		conditions = append(conditions, conditionsEgress)
	}
	// We cannot call findByCondition because we need to pass an array of conditions
	selectOp := []ovsdb.Operation{{
		Op:      "select",
		Table:   "Mirror",
		Where:   conditions,
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

func (ovsd *OvsDriver) CheckMirrorConsumerWithPorts(mirrorName string, portUUIDStr string) (bool, error) {
	portUUID := ovsdb.UUID{GoUUID: portUUIDStr}

	// output_port = Output port for selected packets
	conditionOutput := ovsdb.NewCondition("output_port", ovsdb.ConditionIncludes, portUUID)

	_, err := ovsd.findByCondition("Mirror", conditionOutput, []string{"name"})

	if err != nil {
		return false, err
	}
	return true, nil
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

// FindInterfacesWithError returns the interfaces which are in error state
func (ovsd *OvsDriver) FindInterfacesWithError() ([]string, error) {
	selectOp := ovsdb.Operation{
		Op:      "select",
		Columns: []string{"name", "error"},
		Table:   "Interface",
	}
	transactionResult, err := ovsd.ovsdbTransact([]ovsdb.Operation{selectOp})
	if err != nil {
		return nil, err
	}
	if len(transactionResult) != 1 {
		return nil, fmt.Errorf("no transaction result")
	}
	operationResult := transactionResult[0]
	if operationResult.Error != "" {
		return nil, fmt.Errorf(operationResult.Error)
	}

	var names []string
	for _, row := range operationResult.Rows {

		if !hasError(row) {
			continue
		}
		names = append(names, fmt.Sprintf("%v", row["name"]))
	}
	if len(names) > 0 {
		log.Printf("found %d interfaces with error", len(names))
	}
	return names, nil
}

func hasError(row map[string]interface{}) bool {
	v := row["error"]
	switch x := v.(type) {
	case string:
		return x != ""
	default:
		return false
	}
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

	mirror := make(map[string]interface{})
	mirror["name"] = mirrorName

	// Add an entry in Port table
	mirrorOp := ovsdb.Operation{
		Op:       "insert",
		Table:    "Mirror",
		Row:      mirror,
		UUIDName: mirrorUUIDStr,
	}

	return mirrorUUID, &mirrorOp
}

func attachPortToMirrorProducerOperation(portUUID ovsdb.UUID, mirrorName string, ingress, egress bool) *ovsdb.Operation {
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

	return &mutateOp
}

func attachPortToMirrorConsumerOperation(portUUID ovsdb.UUID, mirrorName string) *ovsdb.Operation {
	mutateSet, _ := ovsdb.NewOvsSet(portUUID)
	// output_port = Output port for selected packets
	mutation := ovsdb.NewMutation("output_port", ovsdb.MutateOperationInsert, mutateSet)

	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Mirror",
		Mutations: []ovsdb.Mutation{*mutation},
		Where:     []ovsdb.Condition{condition},
	}

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

	return &mutateOp
}

func detachPortFromMirrorOperation(portUUID ovsdb.UUID, mirrorName string, mirrorType int) *ovsdb.Operation {
	// mutate the Ports column of the row in the Bridge table
	var mutations []ovsdb.Mutation = []ovsdb.Mutation{}
	switch mirrorType {
	case MirrorProducer:
		mutateSet, _ := ovsdb.NewOvsSet(portUUID)
		// select_src_port = Ports on which arriving packets are selected for mirroring
		mutationIngress := ovsdb.NewMutation("select_src_port", ovsdb.MutateOperationDelete, mutateSet)
		// select_dst_port = Ports on which departing packets are selected for mirroring
		mutationEgress := ovsdb.NewMutation("select_dst_port", ovsdb.MutateOperationDelete, mutateSet)
		mutations = append(mutations, *mutationIngress, *mutationEgress)
	case MirrorConsumer:
		// output_port = Output port for selected packets
		mutationOutput := ovsdb.NewMutation("output_port", ovsdb.MutateOperationDelete, portUUID)
		mutations = append(mutations, *mutationOutput)
	default:
		log.Printf("skipping detatch mirror operation because mirrorType is unknown for mirror %s", mirrorName)
	}

	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, mirrorName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Mirror",
		Mutations: mutations,
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

func deleteInterfaceOperation(intfName string) *ovsdb.Operation {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, intfName)
	intfOp := ovsdb.Operation{
		Op:    "delete",
		Table: "Interface",
		Where: []ovsdb.Condition{condition},
	}

	return &intfOp
}

func deletePortOperation(intfName string) *ovsdb.Operation {
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, intfName)
	portOp := ovsdb.Operation{
		Op:    "delete",
		Table: "Port",
		Where: []ovsdb.Condition{condition},
	}

	return &portOp
}

func detachPortOperation(portUUID ovsdb.UUID, bridgeName string) *ovsdb.Operation {
	// mutate the Ports column of the row in the Bridge table
	mutateSet, _ := ovsdb.NewOvsSet(portUUID)
	mutation := ovsdb.NewMutation("ports", ovsdb.MutateOperationDelete, mutateSet)
	condition := ovsdb.NewCondition("name", ovsdb.ConditionEqual, bridgeName)
	mutateOp := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []ovsdb.Mutation{*mutation},
		Where:     []ovsdb.Condition{condition},
	}

	return &mutateOp
}

// utility function to convert an element (UUID or OvsSet) to an array of UUIDs
func convertToArray(elem interface{}) ([]interface{}, error) {
	elemType := reflect.TypeOf(elem)
	if elemType.Kind() == reflect.Struct {
		if elemType.Name() == "UUID" {
			return []interface{}{elem}, nil
		} else if elemType.Name() == "OvsSet" {
			return elem.(ovsdb.OvsSet).GoSet, nil
		}
		return nil, errors.New("struct with unknown types")
	} else {
		return nil, errors.New("unknown type")
	}
}
