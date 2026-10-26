// SPDX-License-Identifier: MIT

package ethernetip

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/encap"
)

func TestCIPErrorError(t *testing.T) {
	tests := []struct {
		name string
		err  *CIPError
		want string
	}{
		{
			name: "path and status",
			err: &CIPError{Service: cip.ServiceGetAttributeSingle,
				Path: cip.AttributePath(cip.ClassIdentity, 1, 9), Status: cip.StatusAttributeNotSupported},
			want: "ethernetip: " + cip.ServiceName(cip.ClassIdentity, cip.ServiceGetAttributeSingle) +
				" @1/1/9: attribute not supported (0x14)",
		},
		{
			name: "no path",
			err:  &CIPError{Service: cip.ServiceGetAttributesAll, Status: cip.StatusServiceNotSupported},
			want: "ethernetip: " + cip.ServiceGetAttributesAll.String() + ": service not supported (0x08)",
		},
		{
			name: "connection failure extended",
			err: &CIPError{Service: cip.ServiceForwardOpen, Path: cip.ConnectionManagerPath(),
				Status: cip.StatusConnectionFailure, Extended: []uint16{0x0100, 0x0002}},
			want: "ethernetip: " + cip.ServiceName(cip.ClassConnectionManager, cip.ServiceForwardOpen) +
				" @6/1: connection failure (0x01), extended 0x0100 (" + cip.ConnStatusInUse.String() + ") 0x0002",
		},
		{
			name: "other status with extended words",
			err: &CIPError{Service: cip.ServiceSetAttributeSingle, Status: cip.StatusPathSegmentError,
				Extended: []uint16{0x0001, 0xABCD}},
			want: "ethernetip: " + cip.ServiceSetAttributeSingle.String() + ": path segment error (0x04), extended 0x0001 0xABCD",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCIPErrorExtendedStatus(t *testing.T) {
	e := &CIPError{Status: cip.StatusConnectionFailure}
	if v, ok := e.ExtendedStatus(); ok || v != 0 {
		t.Errorf("ExtendedStatus() = %#x, %v; want 0, false", v, ok)
	}
	e.Extended = []uint16{0x0113, 7}
	if v, ok := e.ExtendedStatus(); !ok || v != 0x0113 {
		t.Errorf("ExtendedStatus() = %#x, %v; want 0x0113, true", v, ok)
	}
}

func TestCIPErrorIs(t *testing.T) {
	for s := 0; s < 0x100; s++ {
		e := &CIPError{Status: cip.GeneralStatus(s)}
		want := s == 0x08 || s == 0x14
		if got := errors.Is(e, ErrUnsupported); got != want {
			t.Errorf("status 0x%02X: errors.Is(ErrUnsupported) = %v, want %v", s, got, want)
		}
		if errors.Is(e, ErrSession) || errors.Is(e, ErrProtocol) {
			t.Errorf("status 0x%02X matches an unrelated sentinel", s)
		}
	}
	wrapped := fmt.Errorf("read: %w", &CIPError{Status: cip.StatusAttributeNotSupported})
	if !errors.Is(wrapped, ErrUnsupported) {
		t.Error("wrapped CIPError 0x14 does not match ErrUnsupported")
	}
}

func TestEncapError(t *testing.T) {
	e := &EncapError{Command: encap.CommandSendRRData, Status: encap.StatusInvalidSessionHandle}
	if got, want := e.Error(), "ethernetip: SendRRData: invalid session handle (0x0064)"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, ErrSession) {
		t.Error("EncapError does not match ErrSession")
	}
	if errors.Is(e, ErrUnsupported) {
		t.Error("invalid session handle matches ErrUnsupported")
	}
	if errors.Is(e, ErrProtocol) {
		t.Error("EncapError matches ErrProtocol")
	}
	u := &EncapError{Command: encap.Command(0x99), Status: encap.StatusInvalidCommand}
	if !errors.Is(u, ErrUnsupported) || !errors.Is(u, ErrSession) {
		t.Error("invalid command must match ErrUnsupported and ErrSession")
	}
	if !strings.Contains(u.Error(), "0x0001") {
		t.Errorf("Error() = %q, want the status code", u.Error())
	}
}

func TestStatusOf(t *testing.T) {
	if s, ok := StatusOf(nil); ok || s != 0 {
		t.Errorf("StatusOf(nil) = %v, %v", s, ok)
	}
	if _, ok := StatusOf(ErrTimeout); ok {
		t.Error("StatusOf(ErrTimeout) reported a status")
	}
	err := fmt.Errorf("x: %w", &CIPError{Status: cip.StatusPathDestinationUnknown})
	if s, ok := StatusOf(err); !ok || s != cip.StatusPathDestinationUnknown {
		t.Errorf("StatusOf = %v, %v", s, ok)
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{
		StateDisconnected: "disconnected",
		StateConnecting:   "connecting",
		StateConnected:    "connected",
		StateTimedOut:     "timed-out",
		State(42):         "unknown",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestNopMetrics(t *testing.T) {
	// NopMetrics must satisfy Metrics and accept nil arguments.
	var m Metrics = NopMetrics{}
	m.OnConnect(nil)
	m.OnDisconnect(nil, errors.New("x"))
	m.OnPacketSent(nil, encap.CommandNOP, 24)
	m.OnPacketReceived(nil, encap.CommandNOP, 24)
	m.OnDecodeError(nil, ErrProtocol)
}
