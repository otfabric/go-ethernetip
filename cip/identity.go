// SPDX-License-Identifier: MIT

package cip

import (
	"fmt"
	"strings"
)

// Revision is a major and minor revision.
type Revision struct {
	Major uint8
	Minor uint8
}

// String returns for example "2.3".
func (r Revision) String() string { return fmt.Sprintf("%d.%d", r.Major, r.Minor) }

// IdentityStatus is the status word of the Identity object (attribute 5).
type IdentityStatus uint16

// Identity status bits.
const (
	StatusOwned                    IdentityStatus = 0x0001
	StatusConfigured               IdentityStatus = 0x0004
	StatusMinorRecoverableFault    IdentityStatus = 0x0100
	StatusMinorUnrecoverableFault  IdentityStatus = 0x0200
	StatusMajorRecoverableFault    IdentityStatus = 0x0400
	StatusMajorUnrecoverableFault  IdentityStatus = 0x0800
	statusExtendedDeviceStatusMask IdentityStatus = 0x00F0
)

// ExtendedDeviceStatus returns bits 4..7 of the status word.
func (s IdentityStatus) ExtendedDeviceStatus() uint8 {
	return uint8((s & statusExtendedDeviceStatusMask) >> 4)
}

// String returns the set flags joined with "|", for example
// "OWNED|CONFIGURED", and "" when none is set.
func (s IdentityStatus) String() string {
	var parts []string
	for _, f := range []struct {
		bit  IdentityStatus
		name string
	}{
		{StatusOwned, "OWNED"},
		{StatusConfigured, "CONFIGURED"},
		{StatusMinorRecoverableFault, "MINOR_RECOVERABLE_FAULT"},
		{StatusMinorUnrecoverableFault, "MINOR_UNRECOVERABLE_FAULT"},
		{StatusMajorRecoverableFault, "MAJOR_RECOVERABLE_FAULT"},
		{StatusMajorUnrecoverableFault, "MAJOR_UNRECOVERABLE_FAULT"},
	} {
		if s&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, "|")
}

// Identity is the identity of a device: the attributes of the Identity
// object instance 1, as Get_Attributes_All and ListIdentity carry them.
type Identity struct {
	VendorID     uint16
	DeviceType   DeviceType
	ProductCode  uint16
	Revision     Revision
	Status       IdentityStatus
	SerialNumber uint32
	ProductName  string
	// State is attribute 8. It is carried by ListIdentity; 0xFF means
	// "default" (not implemented).
	State uint8
}

// String returns for example
// "OpENer PC (vendor 1, Communications Adapter, product 65001, rev 2.3, serial 0x075BCD15)".
func (id Identity) String() string {
	return fmt.Sprintf("%s (vendor %d, %s, product %d, rev %s, serial 0x%08X)",
		id.ProductName, id.VendorID, id.DeviceType, id.ProductCode, id.Revision, id.SerialNumber)
}

// AppendAttributes appends attributes 1 to 7, as Get_Attributes_All
// returns them.
func (id Identity) AppendAttributes(b []byte) ([]byte, error) {
	b = AppendUint16(b, id.VendorID)
	b = AppendUint16(b, uint16(id.DeviceType))
	b = AppendUint16(b, id.ProductCode)
	b = append(b, id.Revision.Major, id.Revision.Minor)
	b = AppendUint16(b, uint16(id.Status))
	b = AppendUint32(b, id.SerialNumber)
	return AppendShortString(b, id.ProductName)
}

// DecodeIdentity decodes attributes 1 to 7 from the start of a
// Get_Attributes_All reply of the Identity object. Further attributes some
// devices append (state, configuration consistency value, ...) are ignored,
// except a state octet directly after the product name.
func DecodeIdentity(data []byte) (Identity, error) {
	r := NewReader(data)
	var id Identity
	id.VendorID = r.Uint16()
	id.DeviceType = DeviceType(r.Uint16())
	id.ProductCode = r.Uint16()
	id.Revision = Revision{r.Uint8(), r.Uint8()}
	id.Status = IdentityStatus(r.Uint16())
	id.SerialNumber = r.Uint32()
	id.ProductName = r.ShortString()
	if err := r.Err(); err != nil {
		return id, fmt.Errorf("identity: %w", err)
	}
	id.State = 0xFF
	if r.Len() > 0 {
		id.State = r.Uint8()
	}
	return id, nil
}
