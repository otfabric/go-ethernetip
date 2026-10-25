// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/encap"
)

// Device is a device that answered ListIdentity over UDP.
type Device struct {
	// Addr is the address the reply came from.
	Addr netip.AddrPort
	// Identity is the identity item of the reply. Its Socket is the
	// address the device reports for its TCP port, which differs from Addr
	// behind NAT or when the device is misconfigured.
	Identity encap.IdentityItem
}

// DiscoverOptions configures [Discover].
type DiscoverOptions struct {
	// Address is where the ListIdentity request is sent: a broadcast
	// address ("255.255.255.255", "192.168.1.255") or a single device. The
	// port defaults to 44818. Required.
	Address string
	// Local is the local address to send from (and so the interface);
	// empty picks any.
	Local string
	// Wait is how long replies are collected. Devices delay their reply to
	// a broadcast by up to MaxDelay. Zero means 2 seconds; the context's
	// deadline, when earlier, ends it.
	Wait time.Duration
	// MaxDelay is the largest delay a device may add to its reply, which
	// the request carries in its sender context (milliseconds). Zero
	// leaves it to the device's default (2 seconds by the specification).
	MaxDelay time.Duration
	// MaxDevices stops collecting after that many replies; zero means
	// 1024.
	MaxDevices int
}

// Discover sends one ListIdentity request over UDP and returns the devices
// that answered, in the order of their replies, each address once. It
// sends exactly one datagram: it does not scan.
func Discover(ctx context.Context, opts DiscoverOptions) ([]Device, error) {
	if opts.Address == "" {
		return nil, fmt.Errorf("%w: no discovery address", ethernetip.ErrInvalidOption)
	}
	addr := opts.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(encap.TCPPort))
	}
	dst, err := netip.ParseAddrPort(addr)
	if err != nil {
		ua, rerr := net.ResolveUDPAddr("udp4", addr)
		if rerr != nil {
			return nil, fmt.Errorf("%w: discovery address %q: %w", ethernetip.ErrInvalidOption, opts.Address, rerr)
		}
		dst = ua.AddrPort()
	}
	if opts.Wait == 0 {
		opts.Wait = 2 * time.Second
	}
	if opts.MaxDevices <= 0 {
		opts.MaxDevices = 1024
	}
	var laddr *net.UDPAddr
	if opts.Local != "" {
		if laddr, err = net.ResolveUDPAddr("udp4", opts.Local); err != nil {
			return nil, fmt.Errorf("%w: local address %q: %w", ethernetip.ErrInvalidOption, opts.Local, err)
		}
	}
	conn, err := listenBroadcast(laddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ethernetip.ErrConnectFailed, err)
	}
	defer func() { _ = conn.Close() }()

	var h encap.Header
	h.Command = encap.CommandListIdentity
	_, _ = rand.Read(h.Context[2:])
	if opts.MaxDelay > 0 {
		ms := opts.MaxDelay.Milliseconds()
		if ms > 0xFFFF {
			ms = 0xFFFF
		}
		binary.LittleEndian.PutUint16(h.Context[:], uint16(ms))
	}
	req, _ := encap.Packet{Header: h}.Encode()
	if _, err := conn.WriteToUDPAddrPort(req, dst); err != nil {
		return nil, fmt.Errorf("%w: send ListIdentity: %w", ethernetip.ErrConnectFailed, err)
	}
	end := time.Now().Add(opts.Wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(end) {
		end = dl
	}
	_ = conn.SetReadDeadline(end)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()

	seen := map[netip.AddrPort]bool{}
	var out []Device
	buf := make([]byte, 1500)
	for len(out) < opts.MaxDevices {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			return out, fmt.Errorf("%w: %w", ethernetip.ErrConnectionLost, err)
		}
		pkt, err := encap.Decode(buf[:n])
		if err != nil || pkt.Command != encap.CommandListIdentity || pkt.Context != h.Context || pkt.Status != encap.StatusSuccess {
			continue
		}
		id, err := decodeListIdentity(pkt.Data)
		if err != nil || seen[from] {
			continue
		}
		seen[from] = true
		out = append(out, Device{Addr: from, Identity: id})
	}
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, ctx.Err()
	}
	return out, nil
}

// ListIdentity asks one device for its identity over UDP and returns the
// first reply. addr is the device's address; the port defaults to 44818.
func ListIdentity(ctx context.Context, addr string) (Device, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	devs, err := Discover(ctx, DiscoverOptions{Address: addr, Wait: time.Hour, MaxDevices: 1})
	if err != nil {
		return Device{}, err
	}
	if len(devs) == 0 {
		return Device{}, fmt.Errorf("%w: no ListIdentity reply from %s", ethernetip.ErrTimeout, addr)
	}
	return devs[0], nil
}

// listenBroadcast opens a UDP socket that may send to broadcast addresses.
// The Go runtime sets SO_BROADCAST on IPv4 datagram sockets.
func listenBroadcast(laddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", laddr)
}
