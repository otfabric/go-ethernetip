// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
)

// unconnected returns a client that never connected: a request that
// passes its argument checks fails with ErrNotConnected.
func unconnected(t *testing.T) *Client {
	t.Helper()
	c, err := New("192.0.2.1", WithLogger(ethernetip.NopLogger()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResetTypeRange(t *testing.T) {
	c := unconnected(t)
	if err := c.Reset(context.Background(), cip.ClassIdentity, 1, 255); errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("reset type 255: %v", err)
	}
	if err := c.Reset(context.Background(), cip.ClassIdentity, 1, 256); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("reset type 256: %v", err)
	}
}

func TestGetAttributeListLimits(t *testing.T) {
	c := unconnected(t)
	ids := make([]uint16, 0x10000)
	sizes := make([]int, len(ids))
	// 65535 attributes pass the count check; the request is then too
	// large for an Unconnected Data item.
	if _, err := c.GetAttributeList(context.Background(), cip.ClassIdentity, 1, ids[:0xFFFF], sizes[:0xFFFF]); err == nil || strings.Contains(err.Error(), "above 65535") {
		t.Fatalf("65535 attributes: %v", err)
	}
	if _, err := c.GetAttributeList(context.Background(), cip.ClassIdentity, 1, ids, sizes); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("65536 attributes: %v", err)
	}
	if _, err := c.GetAttributeList(context.Background(), cip.ClassIdentity, 1, []uint16{1, 2}, []int{2, -1}); !errors.Is(err, ethernetip.ErrInvalidOption) {
		t.Fatalf("negative size: %v", err)
	}
}

func TestDecodeAttributeListStatusRange(t *testing.T) {
	// 0x00FF is a general status (no value follows); 0x0100 is not one,
	// and must not be taken for success.
	vals, err := decodeAttributeList([]byte{1, 0, 7, 0, 0xFF, 0x00}, []int{2})
	if err != nil || len(vals) != 1 || vals[0].Status != 0xFF {
		t.Fatalf("status 0x00FF: %+v %v", vals, err)
	}
	if _, err := decodeAttributeList([]byte{1, 0, 7, 0, 0x00, 0x01, 0xAA, 0xBB}, []int{2}); err == nil {
		t.Fatal("status 0x0100 accepted")
	}
}

func TestEncapTimeout(t *testing.T) {
	for d, want := range map[time.Duration]uint16{
		-time.Second:                 0,
		500 * time.Millisecond:       0,
		5 * time.Second:              5,
		0xFFFF * time.Second:         0xFFFF,
		0x10000 * time.Second:        0xFFFF,
		time.Duration(math.MaxInt64): 0xFFFF,
	} {
		if got := encapTimeout(d); got != want {
			t.Errorf("encapTimeout(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestMicroseconds(t *testing.T) {
	for d, want := range map[time.Duration]uint32{
		-time.Second:     0,
		time.Microsecond: 1,
		time.Duration(math.MaxUint32) * time.Microsecond:   math.MaxUint32,
		time.Duration(math.MaxUint32+1) * time.Microsecond: math.MaxUint32,
	} {
		if got := microseconds(d); got != want {
			t.Errorf("microseconds(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestNextSerialWraps(t *testing.T) {
	c := unconnected(t)
	c.serial.Store(0xFFFE)
	if s := c.nextSerial(); s != 0xFFFF {
		t.Fatalf("serial %#x", s)
	}
	if s := c.nextSerial(); s != 0 {
		t.Fatalf("serial after wrap %#x", s)
	}
}

func TestMaxDelayField(t *testing.T) {
	for d, want := range map[time.Duration]uint16{
		-time.Second:               0,
		1500 * time.Microsecond:    1,
		0xFFFF * time.Millisecond:  0xFFFF,
		0x10000 * time.Millisecond: 0xFFFF,
	} {
		if got := maxDelayField(d); got != want {
			t.Errorf("maxDelayField(%v) = %d, want %d", d, got, want)
		}
	}
}
