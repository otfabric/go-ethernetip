// SPDX-License-Identifier: MIT

package scanner

import (
	"errors"
	"math"
	"testing"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
)

func TestRPIMicroseconds(t *testing.T) {
	if us, err := rpiMicroseconds(maxRPI); err != nil || us != math.MaxUint32 {
		t.Fatalf("max RPI: %d %v", us, err)
	}
	if us, err := rpiMicroseconds(time.Microsecond); err != nil || us != 1 {
		t.Fatalf("1 µs: %d %v", us, err)
	}
	for _, d := range []time.Duration{0, 999 * time.Nanosecond, -time.Second, maxRPI + time.Microsecond} {
		if _, err := rpiMicroseconds(d); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("rpiMicroseconds(%v) = %v", d, err)
		}
	}
}

func TestConnectionSize(t *testing.T) {
	if n, err := connectionSize(0xFFFF); err != nil || n != 0xFFFF {
		t.Fatalf("65535: %d %v", n, err)
	}
	for _, n := range []int{-1, 0x10000} {
		if _, err := connectionSize(n); !errors.Is(err, ethernetip.ErrInvalidOption) {
			t.Errorf("connectionSize(%d) = %v", n, err)
		}
	}
}
