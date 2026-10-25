// SPDX-License-Identifier: MIT

package cip

import (
	"fmt"
	"sort"
)

// Class is a CIP object class code.
type Class uint16

// String returns the name of the class, for example "Identity", or
// "class 0x1234" for a class the catalog does not name.
func (c Class) String() string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return fmt.Sprintf("class 0x%02X", uint16(c))
}

// VendorSpecific reports whether the class is a vendor extension (the
// Rockwell Logix objects) rather than a CIP object.
func (c Class) VendorSpecific() bool { return vendorClasses[c] }

// Service is a CIP service code, without the reply bit (0x80). Codes 0x00 to
// 0x31 are common services with one meaning everywhere; codes 0x32 to 0x4A
// are reserved; codes from 0x4B on are object-specific: their meaning
// depends on the class the request is addressed to (see [ServiceName]).
type Service uint8

// ReplyBit is set in the service code of every response.
const ReplyBit Service = 0x80

// String returns the name of a common service ("Get_Attribute_Single"),
// the name of an object-specific service when only one class in the catalog
// defines its code, and "service 0x4C" otherwise.
func (s Service) String() string {
	s &^= ReplyBit
	if n, ok := serviceNames[s]; ok {
		return n
	}
	var name string
	for k, n := range classServiceNames {
		if k.service == s {
			if name != "" {
				return fmt.Sprintf("service 0x%02X", uint8(s))
			}
			name = n
		}
	}
	if name != "" {
		return name
	}
	return fmt.Sprintf("service 0x%02X", uint8(s))
}

// ServiceName returns the name of service s addressed to an object of class
// c: "Read_Tag" for 0x4C to the Symbol class, "Read_Template" for 0x4C to the
// Template class.
func ServiceName(c Class, s Service) string {
	s &^= ReplyBit
	if n, ok := classServiceNames[classService{c, s}]; ok {
		return n
	}
	return s.String()
}

// GeneralStatus is the general status of a CIP response.
type GeneralStatus uint8

// String returns the meaning of the status, for example
// "path destination unknown".
func (g GeneralStatus) String() string {
	if n, ok := generalStatusNames[g]; ok {
		return n
	}
	return fmt.Sprintf("general status 0x%02X", uint8(g))
}

// ConnectionStatus is an extended status of the Connection Manager, carried
// as the first additional status word with general status 0x01.
type ConnectionStatus uint16

// String returns the meaning of the status, for example
// "invalid connection size".
func (c ConnectionStatus) String() string {
	if n, ok := connectionStatusNames[c]; ok {
		return n
	}
	return fmt.Sprintf("connection status 0x%04X", uint16(c))
}

// DeviceType is the device type of the Identity object (attribute 2).
type DeviceType uint16

// String returns the name of the device type, for example
// "Communications Adapter".
func (d DeviceType) String() string {
	if n, ok := deviceTypeNames[d]; ok {
		return n
	}
	return fmt.Sprintf("device type 0x%02X", uint16(d))
}

type vendorEntry struct {
	id   uint16
	name string
}

// VendorName returns the name ODVA's public vendor list gives vendor ID id,
// and "" when it is not in the list.
func VendorName(id uint16) string {
	i := sort.Search(len(vendors), func(i int) bool { return vendors[i].id >= id })
	if i < len(vendors) && vendors[i].id == id {
		return vendors[i].name
	}
	return ""
}

// typeKind is how the value of an elementary data type is represented.
type typeKind uint8

const (
	kindBool typeKind = iota + 1
	kindInt
	kindUint
	kindFloat
	kindString
	kindBytes
)

type typeInfo struct {
	name string
	size int
	kind typeKind
}

// DataType is the code of a CIP elementary data type, as used in Logix tag
// services and EDS parameters.
type DataType uint8

// String returns the name of the type, for example "DINT".
func (t DataType) String() string {
	if i, ok := dataTypeInfo[t]; ok {
		return i.name
	}
	return fmt.Sprintf("type 0x%02X", uint8(t))
}

// Size returns the encoded size in octets of a value of a fixed-size type,
// and 0 for strings, EPATHs and unknown types.
func (t DataType) Size() int { return dataTypeInfo[t].size }

// Known reports whether t is an elementary data type of the catalog.
func (t DataType) Known() bool {
	_, ok := dataTypeInfo[t]
	return ok
}

// IsInteger reports whether t is a signed or unsigned integer type,
// including the bit string types BYTE, WORD, DWORD and LWORD.
func (t DataType) IsInteger() bool {
	k := dataTypeInfo[t].kind
	return k == kindInt || k == kindUint
}

// IsSigned reports whether t is a signed integer type.
func (t DataType) IsSigned() bool { return dataTypeInfo[t].kind == kindInt }

// IsFloat reports whether t is REAL or LREAL.
func (t DataType) IsFloat() bool { return dataTypeInfo[t].kind == kindFloat }

// IsString reports whether t is one of the string types.
func (t DataType) IsString() bool { return dataTypeInfo[t].kind == kindString }

// ParseDataType returns the type named name ("DINT", "SHORT_STRING"); the
// match is case-sensitive, as the names are in the specifications.
func ParseDataType(name string) (DataType, bool) {
	for t, i := range dataTypeInfo {
		if i.name == name {
			return t, true
		}
	}
	return 0, false
}
