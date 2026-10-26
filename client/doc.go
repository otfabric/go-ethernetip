// SPDX-License-Identifier: MIT

// Package client is an EtherNet/IP originator of explicit messages.
//
// A [Client] holds one TCP connection and encapsulation session with a
// target. It sends unconnected requests with SendRRData, routed through the
// target's Connection Manager with Unconnected_Send when a route is set
// ([WithRoute]), and opens connected (Class 3) messaging connections with
// Forward_Open ([Client.OpenConnection]), whose requests travel in
// SendUnitData. [Client.ForwardOpen] and [Client.ForwardClose] are also the
// building blocks of the scanner package's I/O connections.
//
// [Discover] and [ListIdentity] find devices with ListIdentity over UDP.
//
// Every call takes a context.Context; a request's wait ends at the earlier
// of the context's deadline and the client's timeout ([WithTimeout]).
// Errors match the sentinels of the root package with errors.Is
// (ErrTimeout, ErrConnectionLost, ErrNotConnected, ...) and carry the
// target's answer as *ethernetip.CIPError or *ethernetip.EncapError.
package client
