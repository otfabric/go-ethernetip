// SPDX-License-Identifier: MIT

package client

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/encap"
)

// fakeSocket returns its datagrams and errors in order, then a timeout.
type fakeSocket struct {
	steps []any // []byte or error
}

func (f *fakeSocket) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	from := netip.MustParseAddrPort("192.0.2.1:44818")
	if len(f.steps) == 0 {
		return 0, from, os.ErrDeadlineExceeded
	}
	s := f.steps[0]
	f.steps = f.steps[1:]
	if err, ok := s.(error); ok {
		return 0, from, err
	}
	return copy(b, s.([]byte)), from, nil
}

func readErr(err error) error { return &net.OpError{Op: "read", Net: "udp4", Err: err} }

// A read error such as Windows' WSAEMSGSIZE or WSAECONNRESET skips the
// datagram: the replies after it are still collected.
func TestCollectSkipsReadErrors(t *testing.T) {
	h := encap.Header{Command: encap.CommandListIdentity, Context: [8]byte{1, 2, 3}}
	f := &fakeSocket{steps: []any{readErr(syscall.EMSGSIZE), readErr(syscall.ECONNRESET), identityReply(t, h, "after errors")}}
	devs, err := collect(f, h.Context, 10)
	if err != nil || len(devs) != 1 || devs[0].Identity.ProductName != "after errors" {
		t.Fatalf("collect = %+v, %v", devs, err)
	}
}

// A socket that keeps failing, or is closed, ends the collection with
// ErrConnectionLost and the devices found so far.
func TestCollectFailingSocket(t *testing.T) {
	h := encap.Header{Command: encap.CommandListIdentity, Context: [8]byte{4}}
	steps := []any{identityReply(t, h, "first")}
	for range maxDiscoverErrors + 1 {
		steps = append(steps, readErr(syscall.EIO))
	}
	devs, err := collect(&fakeSocket{steps: steps}, h.Context, 10)
	if !errors.Is(err, ethernetip.ErrConnectionLost) || len(devs) != 1 {
		t.Fatalf("after %d errors: %+v, %v", maxDiscoverErrors+1, devs, err)
	}
	// maxDiscoverErrors in a row are skipped.
	steps = steps[:1+maxDiscoverErrors]
	if devs, err := collect(&fakeSocket{steps: steps}, h.Context, 10); err != nil || len(devs) != 1 {
		t.Fatalf("after %d errors: %+v, %v", maxDiscoverErrors, devs, err)
	}
	if _, err := collect(&fakeSocket{steps: []any{net.ErrClosed}}, h.Context, 10); !errors.Is(err, ethernetip.ErrConnectionLost) {
		t.Fatalf("closed socket: %v", err)
	}
}
