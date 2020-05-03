package openflow13

import (
	"encoding/binary"
	"errors"

	"github.com/contiv/libOpenflow/util"
)

// Nicira extension messages.
const (
	Type_SetFlowFormat     = 12
	Type_FlowModTableId    = 15
	Type_SetPacketInFormat = 16
	Type_SetControllerId   = 20
	Type_TlvTableMod       = 24
	Type_TlvTableRequest   = 25
	Type_TlvTableReply     = 26
	Type_Resume            = 28
	Type_CtFlushZone       = 29
)

// ofpet_tlv_table_mod_failed_code 1.3
const (
	OFPERR_NXTTMFC_BAD_COMMAND     = 16
	OFPERR_NXTTMFC_BAD_OPT_LEN     = 17
	ERR_NXTTMFC_BAD_FIELD_IDX      = 18
	OFPERR_NXTTMFC_TABLE_FULL      = 19
	OFPERR_NXTTMFC_ALREADY_MAPPED  = 20
	OFPERR_NXTTMFC_DUP_ENTRY       = 21
	OFPERR_NXTTMFC_INVALID_TLV_DEL = 38
)

// Flow entry eviction constants
const (
	ONF_ET_SET_EVICTION         = 1925
	ONF_ET_GET_EVICTION_REQUEST = 1926
	ONF_ET_GET_EVICTION_REPLY   = 1927

	ONFIST_ET_EVICTION_IMPORTANCE = 1920
)

func NewNXTVendorHeader(msgType uint32) *VendorHeader {
	h := NewOfp13Header()
	h.Type = Type_Experimenter
	return &VendorHeader{
		Header:           h,
		Vendor:           NxExperimenterID,
		ExperimenterType: msgType,
	}
}

type ControllerID struct {
	pad [6]byte
	ID  uint16
}

func (c *ControllerID) Len() uint16 {
	return uint16(len(c.pad) + 2)
}

func (c *ControllerID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(c.Len()))
	n := 6
	binary.BigEndian.PutUint16(data[n:], c.ID)
	return data, nil
}

func (c *ControllerID) UnmarshalBinary(data []byte) error {
	if len(data) < int(c.Len()) {
		return errors.New("the []byte is too short to unmarshal a full ControllerID message")
	}
	n := 6
	c.ID = binary.BigEndian.Uint16(data[n:])
	return nil
}

func NewSetControllerID(id uint16) *VendorHeader {
	msg := NewNXTVendorHeader(Type_SetControllerId)
	msg.VendorData = &ControllerID{
		ID: id,
	}
	return msg
}

type TLVTableMap struct {
	OptClass  uint16
	OptType   uint8
	OptLength uint8
	Index     uint16
	pad       [2]byte
}

func (t *TLVTableMap) Len() uint16 {
	return uint16(len(t.pad) + 6)
}

func (t *TLVTableMap) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	n := 0
	binary.BigEndian.PutUint16(data[n:], t.OptClass)
	n += 2
	data[n] = t.OptType
	n += 1
	data[n] = t.OptLength
	n += 1
	binary.BigEndian.PutUint16(data[n:], t.Index)
	return data, nil
}

func (t *TLVTableMap) UnmarshalBinary(data []byte) error {
	if len(data) < int(t.Len()) {
		return errors.New("the []byte is too short to unmarshal a full TLVTableMap message")
	}
	n := 0
	t.OptClass = binary.BigEndian.Uint16(data[n:])
	n += 2
	t.OptType = data[n]
	n += 1
	t.OptLength = data[n]
	n += 1
	t.Index = binary.BigEndian.Uint16(data[n:])
	return nil
}

type TLVTableMod struct {
	Command uint16
	pad     [6]byte
	TlvMaps []*TLVTableMap
}

func (t *TLVTableMod) Len() uint16 {
	length := uint16(8)
	for _, tlvMap := range t.TlvMaps {
		length += tlvMap.Len()
	}
	return length
}

func (t *TLVTableMod) MarshalBinary() (data []byte, err error) {
	data = make([]byte, t.Len())
	n := 0
	binary.BigEndian.PutUint16(data[n:], t.Command)
	n += 2
	n += 6
	for _, tlvMap := range t.TlvMaps {
		tlvData, err := tlvMap.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], tlvData)
		n += len(tlvData)
	}
	return data, nil
}

func (t *TLVTableMod) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("the []byte is too short to unmarshal a full TLVTableMod message")
	}
	n := 0
	t.Command = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6

	for n < len(data) {
		tlvMap := new(TLVTableMap)
		err := tlvMap.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += int(tlvMap.Len())
		t.TlvMaps = append(t.TlvMaps, tlvMap)
	}
	return nil
}

func NewTLVTableMod(command uint16, tlvMaps []*TLVTableMap) *TLVTableMod {
	return &TLVTableMod{
		Command: command,
		TlvMaps: tlvMaps,
	}
}

func NewTLVTableModMessage(tlvMod *TLVTableMod) *VendorHeader {
	msg := NewNXTVendorHeader(Type_TlvTableMod)
	msg.VendorData = tlvMod
	return msg
}

type TLVTableReply struct {
	MaxSpace  uint32
	MaxFields uint16
	reserved  [10]byte
	TlvMaps   []*TLVTableMap
}

func (t *TLVTableReply) Len() uint16 {
	length := uint16(16)
	for _, tlvMap := range t.TlvMaps {
		length += tlvMap.Len()
	}
	return length
}

func (t *TLVTableReply) MarshalBinary() (data []byte, err error) {
	data = make([]byte, t.Len())
	n := 0
	binary.BigEndian.PutUint32(data[n:], t.MaxSpace)
	n += 4
	binary.BigEndian.PutUint16(data[n:], t.MaxFields)
	n += 2
	n += 10
	for _, tlvMap := range t.TlvMaps {
		tlvData, err := tlvMap.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], tlvData)
		n += len(tlvData)
	}
	return data, nil
}

func (t *TLVTableReply) UnmarshalBinary(data []byte) error {
	n := 0
	t.MaxSpace = binary.BigEndian.Uint32(data[n:])
	n += 4
	t.MaxFields = binary.BigEndian.Uint16(data[n:])
	n += 2
	t.reserved = [10]byte{}
	copy(t.reserved[0:], data[n:n+10])
	n += 10
	for n < len(data) {
		tlvMap := new(TLVTableMap)
		err := tlvMap.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += int(tlvMap.Len())
		t.TlvMaps = append(t.TlvMaps, tlvMap)
	}
	return nil
}

func NewTLVTableRequest() *VendorHeader {
	return NewNXTVendorHeader(Type_TlvTableRequest)
}

func decodeVendorData(experimenterType uint32, data []byte) (msg util.Message, err error) {
	switch experimenterType {
	case Type_SetControllerId:
		msg = new(ControllerID)
	case Type_TlvTableMod:
		msg = new(TLVTableMod)
	case Type_TlvTableReply:
		msg = new(TLVTableReply)
	case Type_BundleCtrl:
		msg = new(BundleControl)
	case Type_BundleAdd:
		msg = new(BundleAdd)
	case ONF_ET_SET_EVICTION:
		msg = new(SetFlowEviction)
	case ONF_ET_GET_EVICTION_REQUEST:
		msg = new(GetFlowEviction)
	case ONF_ET_GET_EVICTION_REPLY:
		msg = new(SetFlowEviction)
	}
	err = msg.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return msg, err
}

type SetFlowEviction struct {
	TableID         uint8
	EvictionEnabled bool
	pad             [6]byte
}

func (e *SetFlowEviction) Len() uint16 {
	return uint16(2 + len(e.pad))
}

func (e *SetFlowEviction) MarshalBinary() (data []byte, err error) {
	data = make([]byte, e.Len())
	n := 0
	data[n] = e.TableID
	n += 1
	if e.EvictionEnabled {
		data[n] = 1
	} else {
		data[n] = 0
	}
	n += 1
	return data, nil
}

func (e *SetFlowEviction) UnmarshalBinary(data []byte) error {
	if len(data) < int(e.Len()) {
		return errors.New("the []byte is too short to unmarshal a full SetFlowEviction message")
	}
	n := 0
	e.TableID = data[n]
	n += 1
	e.EvictionEnabled = (data[n] != 0)
	n += 1
	return nil
}

func NewSetFlowEvictionMessage(tableID uint8, enabled bool) *VendorHeader {
	h := NewOfp13Header()
	h.Type = Type_Experimenter
	setFlowEviction := &SetFlowEviction{
		TableID:         tableID,
		EvictionEnabled: enabled,
	}
	return &VendorHeader{
		Header:           h,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: ONF_ET_SET_EVICTION,
		VendorData:       setFlowEviction,
	}
}

type GetFlowEviction struct {
	TableID uint8
	pad     [7]byte
}

func (e *GetFlowEviction) Len() uint16 {
	return uint16(1 + len(e.pad))
}

func (e *GetFlowEviction) MarshalBinary() (data []byte, err error) {
	data = make([]byte, e.Len())
	n := 0
	data[n] = e.TableID
	n += 1
	return data, nil
}

func (e *GetFlowEviction) UnmarshalBinary(data []byte) error {
	if len(data) < int(e.Len()) {
		return errors.New("the []byte is too short to unmarshal a full SetFlowEviction message")
	}
	n := 0
	e.TableID = data[n]
	n += 1
	return nil
}

func NewGetFlowEvictionRequestMessage(tableID uint8) *VendorHeader {
	h := NewOfp13Header()
	h.Type = Type_Experimenter
	getFlowEviction := &GetFlowEviction{
		TableID: tableID,
	}
	return &VendorHeader{
		Header:           h,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: ONF_ET_GET_EVICTION_REQUEST,
		VendorData:       getFlowEviction,
	}
}

func NewGetFlowEvictionReplyMessage(tableID uint8) *VendorHeader {
	h := NewOfp13Header()
	h.Type = Type_Experimenter
	getFlowEviction := &GetFlowEviction{
		TableID: tableID,
	}
	return &VendorHeader{
		Header:           h,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: ONF_ET_GET_EVICTION_REPLY,
		VendorData:       getFlowEviction,
	}
}

type EvictionImportanceInstruction struct {
	*InstrHeader
	Vendor           uint32
	ExperimenterType uint32
	Importance       uint16
	pad              [4]byte
}

func (i *EvictionImportanceInstruction) Len() uint16 {
	return i.InstrHeader.Len() + 14
}

func (i *EvictionImportanceInstruction) MarshalBinary() (data []byte, err error) {
	data = make([]byte, i.Len())
	i.Length = i.Len()
	d, err := i.InstrHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, d)
	n := len(d)
	binary.BigEndian.PutUint32(data[n:], i.Vendor)
	n += 4
	binary.BigEndian.PutUint32(data[n:], i.ExperimenterType)
	n += 4
	binary.BigEndian.PutUint16(data[n:], i.Importance)

	return data, nil
}

func (i *EvictionImportanceInstruction) UnmarshalBinary(data []byte) error {
	i.InstrHeader = new(InstrHeader)
	n := 0
	err := i.InstrHeader.UnmarshalBinary(data[:4])
	if err != nil {
		return err
	}
	n += int(i.InstrHeader.Len())
	i.Vendor = binary.BigEndian.Uint32(data[n:])
	n += 4
	i.ExperimenterType = binary.BigEndian.Uint32(data[n:])
	n += 4
	i.Importance = binary.BigEndian.Uint16(data[n:])
	n += 2
	return nil
}

func (i *EvictionImportanceInstruction) AddAction(act Action, prepend bool) error {
	return errors.New("Not supported on this instrction")
}

func NewEvictionImportanceInstruction(importance uint16) *EvictionImportanceInstruction {
	header := &InstrHeader{
		Type:   InstrType_EXPERIMENTER,
		Length: 16,
	}
	return &EvictionImportanceInstruction{
		InstrHeader:      header,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: ONFIST_ET_EVICTION_IMPORTANCE,
		Importance:       importance,
	}
}
