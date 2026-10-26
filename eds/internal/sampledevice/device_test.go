// SPDX-License-Identifier: MIT

package sampledevice

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/scanner"
)

func TestIdentity(t *testing.T) {
	want := cip.KeySegment{VendorID: 65535, DeviceType: 12, ProductCode: 42, Major: 3, Minor: 7}
	if got := Key(); got != want {
		t.Errorf("Key() = %+v, want %+v", got, want)
	}
	if ProductName != "e2e adapter" || DeviceType != 12 {
		t.Errorf("%q %d", ProductName, DeviceType)
	}
}

func TestConfigurationRoundTrip(t *testing.T) {
	for _, d := range []AssemblyConfigurationData{
		{},
		{SpeedSetpoint: 1500, Mode: 2, Padding: 0, Temperature: 21.5},
		{SpeedSetpoint: math.MaxUint16, Mode: -128, Padding: 255, Temperature: -40},
		{Temperature: float32(math.Inf(1))},
	} {
		b := d.Encode()
		if len(b) != AssemblyConfigurationSize {
			t.Fatalf("%d octets, want %d", len(b), AssemblyConfigurationSize)
		}
		got, err := DecodeAssemblyConfiguration(b)
		if err != nil || got != d {
			t.Errorf("round trip of %+v: %+v %v", d, got, err)
		}
	}
	// The layout of the EDS: UINT, SINT, USINT, REAL, 16 bits of padding,
	// little-endian.
	b := AssemblyConfigurationData{SpeedSetpoint: 0x0102, Mode: -1, Padding: 7, Temperature: 1}.Encode()
	want := []byte{0x02, 0x01, 0xFF, 0x07, 0x00, 0x00, 0x80, 0x3F, 0, 0}
	if !bytes.Equal(b, want) {
		t.Errorf("Encode % X, want % X", b, want)
	}
	for _, n := range []int{0, 9, 11} {
		if _, err := DecodeAssemblyConfiguration(make([]byte, n)); err == nil {
			t.Errorf("%d octets decoded", n)
		}
	}
}

func TestChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"RPI min", CheckParamRPI(1000), true},
		{"RPI max", CheckParamRPI(3600000000), true},
		{"RPI default", CheckParamRPI(ParamRPIDefault), true},
		{"RPI below", CheckParamRPI(999), false},
		{"RPI above", CheckParamRPI(3600000001), false},
		{"speed max", CheckParamSpeedSetpoint(3000), true},
		{"speed above", CheckParamSpeedSetpoint(3001), false},
		{"mode min", CheckParamMode(0), true},
		{"mode below", CheckParamMode(-1), false},
		{"mode above", CheckParamMode(3), false},
		{"temperature min", CheckParamTemperature(-40), true},
		{"temperature below", CheckParamTemperature(-40.5), false},
		{"temperature above", CheckParamTemperature(125.01), false},
		{"padding", CheckParamPadding(0), true},
		{"padding above", CheckParamPadding(1), false},
	} {
		if (tc.err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, tc.err)
		}
	}
	if err := CheckParamRPI(1); err == nil || err.Error() != "ParamRPI: 1 out of range" {
		t.Errorf("%v", err)
	}
	if ParamSpeedSetpointDefault != 1500 || ParamTemperatureDefault != 20 || ParamModeDefault != 0 {
		t.Error("defaults")
	}
	if ParamRPI.Number != 1 || ParamRPI.Units != "us" || ParamRPI.Type != cip.TypeUDINT || ParamTemperature.Type != cip.TypeREAL {
		t.Errorf("%+v %+v", ParamRPI, ParamTemperature)
	}
}

func TestEnumString(t *testing.T) {
	for v, want := range map[ModeValue]string{
		ModeValueStopped: "Stopped", ModeValueRunning: "Running", ModeValueFaulted: "Faulted",
		3: "ModeValue(3)", -1: "ModeValue(-1)",
	} {
		if got := v.String(); got != want {
			t.Errorf("%d: %q, want %q", int8(v), got, want)
		}
	}
}

func TestConnections(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  scanner.IOConfig
		want scanner.IOConfig
	}{
		{"exclusive owner", ConnectionExclusiveOwner(), scanner.IOConfig{ConfigInstance: AssemblyConfigurationInstance,
			OutputInstance: AssemblyOutputInstance, InputInstance: AssemblyInputInstance,
			OutputSize: AssemblyOutputSize, InputSize: AssemblyInputSize, RPI: 10 * time.Millisecond}},
		{"input only", ConnectionInputOnly(), scanner.IOConfig{ConfigInstance: 151,
			OutputInstance: AssemblyInputOnlyHeartbeatInstance, InputInstance: 100, InputSize: 32, RPI: 10 * time.Millisecond}},
		{"listen only", ConnectionListenOnly(), scanner.IOConfig{ConfigInstance: 151,
			OutputInstance: AssemblyListenOnlyHeartbeatInstance, InputInstance: 100, InputSize: 32, RPI: 10 * time.Millisecond}},
	} {
		if tc.got.ConfigInstance != tc.want.ConfigInstance || tc.got.OutputInstance != tc.want.OutputInstance ||
			tc.got.InputInstance != tc.want.InputInstance || tc.got.OutputSize != tc.want.OutputSize ||
			tc.got.InputSize != tc.want.InputSize || tc.got.RPI != tc.want.RPI || tc.got.ClassZero ||
			tc.got.ConfigData != nil || tc.got.OutputFormat != nil {
			t.Errorf("%s: %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
	if AssemblyOutputInstance != 150 || AssemblyInputInstance != 100 || AssemblyInputOnlyHeartbeatInstance != 152 || AssemblyListenOnlyHeartbeatInstance != 153 {
		t.Error("assembly instances")
	}
	if time.Duration(ParamRPIDefault)*time.Microsecond != ConnectionExclusiveOwner().RPI {
		t.Error("the RPI is not Param1's default")
	}
}
