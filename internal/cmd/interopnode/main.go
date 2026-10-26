// SPDX-License-Identifier: MIT

// Command interopnode is go-ethernetip behind the container contract of
// otfabric/ethernetip-interop: an adapter ("server") that serves a fixture,
// and an originator ("client") that runs one operation and prints one JSON
// result. The interop tests (package interop) run it in a container on the
// Docker network of the reference implementations, so that it reaches them
// without NAT, as I/O connections need.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	ethernetip "github.com/otfabric/go-ethernetip"
	"github.com/otfabric/go-ethernetip/cip"
	"github.com/otfabric/go-ethernetip/client"
	"github.com/otfabric/go-ethernetip/logix"
	"github.com/otfabric/go-ethernetip/scanner"
	"github.com/otfabric/go-ethernetip/server"
)

const schemaVersion = "1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: interopnode server|client <op>|print-capabilities|version")
		return 2
	}
	switch args[0] {
	case "server":
		return serve(args[1:], stdout, stderr)
	case "client":
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "client needs an operation")
			return 2
		}
		return clientOp(args[1], args[2:], stdout, stderr)
	case "print-capabilities":
		_ = json.NewEncoder(stdout).Encode(capabilities())
		return 0
	case "version":
		_, _ = fmt.Fprintf(stdout, "{\"adapter\":\"go-ethernetip\",\"contract\":\"1.0\"}\n")
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

// Fixture is the fixture document of ethernetip-interop.
type Fixture struct {
	Name     string `json:"name"`
	Identity struct {
		VendorID     uint16 `json:"vendorId"`
		DeviceType   uint16 `json:"deviceType"`
		ProductCode  uint16 `json:"productCode"`
		Revision     string `json:"revision"`
		SerialNumber uint32 `json:"serialNumber"`
		ProductName  string `json:"productName"`
	} `json:"identity"`
	Assemblies []struct {
		Instance uint32 `json:"instance"`
		Kind     string `json:"kind"`
		Size     int    `json:"size"`
	} `json:"assemblies"`
	EchoOutputToInput bool         `json:"echoOutputToInput"`
	Slot              int          `json:"slot"`
	Tags              []FixtureTag `json:"tags"`
}

// FixtureTag is a tag of the logix fixture.
type FixtureTag struct {
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Count   int       `json:"count"`
	Values  []float64 `json:"values"`
	Pattern *struct {
		Multiplier float64 `json:"multiplier"`
		Offset     float64 `json:"offset"`
	} `json:"pattern"`
}

// Value returns element i of the tag's initial value.
func (t FixtureTag) Value(i int) float64 {
	if t.Pattern != nil {
		return float64(i)*t.Pattern.Multiplier + t.Pattern.Offset
	}
	if i < len(t.Values) {
		return t.Values[i]
	}
	return 0
}

func loadFixture(path string) (*Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", path, err)
	}
	return &f, nil
}

func revision(s string) cip.Revision {
	a, b, _ := strings.Cut(s, ".")
	ma, _ := strconv.Atoi(a)
	mi, _ := strconv.Atoi(b)
	return cip.Revision{Major: uint8(ma), Minor: uint8(mi)}
}

func event(w io.Writer, fields map[string]any) {
	b, _ := json.Marshal(fields)
	_, _ = fmt.Fprintf(w, "%s\n", b)
}

func serve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixture := fs.String("fixture", "/fixtures/adapter/fixture.json", "fixture to serve")
	port := fs.Int("port", 44818, "TCP and UDP explicit port")
	ioPort := fs.Int("io-port", 2222, "UDP I/O port")
	ready := fs.String("ready-file", "/run/ethernetip-interop/ready", "readiness file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := loadFixture(*fixture)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 4
	}
	id := cip.Identity{
		VendorID: f.Identity.VendorID, DeviceType: cip.DeviceType(f.Identity.DeviceType), ProductCode: f.Identity.ProductCode,
		Revision: revision(f.Identity.Revision), SerialNumber: f.Identity.SerialNumber, ProductName: f.Identity.ProductName, State: 3,
	}
	srv, err := server.New(server.WithIdentity(id), server.WithSlot(f.Slot),
		server.WithIOAddress(net.JoinHostPort("0.0.0.0", strconv.Itoa(*ioPort))),
		server.WithMaxPacket(65535))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 4
	}
	asms := map[uint32]*server.Assembly{}
	kinds := map[string]server.AssemblyKind{"input": server.AssemblyInput, "output": server.AssemblyOutput, "config": server.AssemblyConfig,
		"input-only": server.AssemblyInputOnly, "listen-only": server.AssemblyListenOnly, "explicit": server.AssemblyOutput}
	for _, a := range f.Assemblies {
		k, ok := kinds[a.Kind]
		if !ok {
			_, _ = fmt.Fprintf(stderr, "assembly kind %q\n", a.Kind)
			return 4
		}
		asm, err := srv.AddAssembly(a.Instance, k, a.Size)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 4
		}
		asms[a.Instance] = asm
	}
	if f.EchoOutputToInput && asms[150] != nil && asms[100] != nil {
		in := asms[100]
		asms[150].OnWrite(func(data []byte, _ bool) { _ = in.SetData(data) })
	}
	if len(f.Tags) > 0 {
		ts := logix.NewTagServer(logix.WithProgramName(f.Name))
		for _, t := range f.Tags {
			if err := addTag(ts, t); err != nil {
				_, _ = fmt.Fprintln(stderr, err)
				return 4
			}
		}
		ts.Attach(srv)
	}
	if err := srv.Listen(net.JoinHostPort("0.0.0.0", strconv.Itoa(*port))); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	if *ready != "" {
		_ = os.WriteFile(*ready, nil, 0o644)
	}
	event(stdout, map[string]any{"event": "ready", "adapter": "go-ethernetip", "address": srv.Addr().String(), "fixture": f.Name})
	select {
	case <-ctx.Done():
		if *ready != "" {
			_ = os.Remove(*ready)
		}
		_ = srv.Close()
		event(stdout, map[string]any{"event": "stopped", "adapter": "go-ethernetip"})
		return 0
	case err := <-done:
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
}

func addTag(ts *logix.TagServer, t FixtureTag) error {
	typ, ok := cip.ParseDataType(t.Type)
	if !ok {
		return fmt.Errorf("tag %s: type %q", t.Name, t.Type)
	}
	n := t.Count
	var dims []int
	if n > 0 {
		dims = []int{n}
	} else {
		n = 1
	}
	if err := ts.AddTag(t.Name, typ, dims...); err != nil {
		return err
	}
	var v logix.Value
	var err error
	if typ.IsFloat() {
		fs := make([]float64, n)
		for i := range fs {
			fs[i] = t.Value(i)
		}
		v, err = logix.Floats(typ, fs...)
	} else {
		is := make([]int64, n)
		for i := range is {
			is[i] = int64(math.Round(t.Value(i)))
		}
		v, err = logix.Ints(typ, is...)
	}
	if err != nil {
		return err
	}
	if typ == cip.TypeBOOL && len(dims) == 0 {
		// Logix BOOL tags hold 0 or 1.
		for i := range v.Data {
			if v.Data[i] != 0 {
				v.Data[i] = 1
			}
		}
	}
	return ts.Set(t.Name, v)
}

func capabilities() map[string]any {
	return map[string]any{
		"schemaVersion": schemaVersion,
		"adapter":       "go-ethernetip",
		"roles":         map[string]bool{"server": true, "client": true},
		"fixtures":      []string{"adapter", "logix"},
		"clientOperations": []string{"list-identity", "list-services", "get-attribute", "set-attribute",
			"get-attributes-all", "multiple-get", "io", "read-tag", "write-tag", "tag-list"},
	}
}

// result is the client result document.
type result map[string]any

type opError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func classify(err error) opError {
	switch {
	case errors.Is(err, ethernetip.ErrTimeout):
		return opError{"timeout", err.Error()}
	case errors.Is(err, ethernetip.ErrConnectFailed):
		return opError{"connect-failed", err.Error()}
	case errors.Is(err, ethernetip.ErrConnectionLost):
		return opError{"connection-lost", err.Error()}
	case errors.Is(err, ethernetip.ErrProtocol):
		return opError{"protocol", err.Error()}
	default:
		return opError{"failed", err.Error()}
	}
}

func clientOp(op string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "", "target host")
	port := fs.Int("port", 44818, "target port")
	timeout := fs.Int("timeout-ms", 5000, "request timeout")
	transport := fs.String("transport", "tcp", "list-identity transport: tcp or udp")
	class := fs.Uint("class", 0, "class")
	instance := fs.Uint("instance", 0, "instance")
	attribute := fs.Uint("attribute", 0, "attribute")
	data := fs.String("data", "", "hex data")
	connected := fs.Bool("connected", false, "use a Class 3 connection")
	route := fs.String("route", "", "route path, for example 1/0")
	var paths multiFlag
	fs.Var(&paths, "path", "@class/instance/attribute (repeatable)")
	cfgInst := fs.Uint("config", 0, "configuration assembly")
	outInst := fs.Uint("output", 0, "O->T assembly")
	inInst := fs.Uint("input", 0, "T->O assembly")
	outSize := fs.Int("output-size", 0, "O->T data size")
	inSize := fs.Int("input-size", 0, "T->O data size")
	rpi := fs.Int("rpi-ms", 10, "RPI in ms")
	dur := fs.Int("duration-ms", 1000, "I/O exchange duration")
	outData := fs.String("output-data", "", "hex output data")
	large := fs.Bool("large", false, "Large_Forward_Open")
	multicast := fs.Bool("multicast", false, "T->O multicast")
	tag := fs.String("tag", "", "tag name")
	count := fs.Int("count", 1, "elements")
	typ := fs.String("type", "", "tag type")
	values := fs.String("values", "", "comma-separated values")
	if err := fs.Parse(args); err != nil || *host == "" {
		if *host == "" {
			_, _ = fmt.Fprintln(stderr, "--host is required")
		}
		return 2
	}
	res := result{"schemaVersion": schemaVersion, "adapter": "go-ethernetip", "operation": op, "ok": false, "error": nil}
	write := func(code int) int {
		_ = json.NewEncoder(stdout).Encode(res)
		return code
	}
	fail := func(err error) int {
		e := classify(err)
		res["error"] = e
		return write(1)
	}
	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Millisecond+time.Duration(*dur)*time.Millisecond+10*time.Second)
	defer cancel()

	if op == "list-identity" && *transport == "udp" {
		dev, err := client.ListIdentity(ctx, addr)
		if err != nil {
			return fail(err)
		}
		res["identity"] = identityDoc(dev.Identity.Identity, dev.Identity.Socket.AddrPort().String())
		res["ok"] = true
		return write(0)
	}
	opts := []client.Option{client.WithTimeout(time.Duration(*timeout) * time.Millisecond)}
	if *route != "" {
		r, err := cip.ParseRoute(*route)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
		opts = append(opts, client.WithRoute(r))
	}
	c, err := client.Dial(ctx, addr, opts...)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = c.Close() }()
	var d client.Doer = c
	if *connected {
		cn, err := c.OpenConnection(ctx, client.ConnectionOptions{Large: *large})
		if err != nil {
			return fail(err)
		}
		defer func() { _ = cn.Close(ctx) }()
		d = cn
	}
	status := func(resp cip.Response, err error) (bool, int) {
		var ce *ethernetip.CIPError
		if err != nil && !errors.As(err, &ce) {
			return false, fail(err)
		}
		res["status"] = int(resp.Status)
		ext := []int{}
		for _, x := range resp.Extended {
			ext = append(ext, int(x))
		}
		res["extendedStatus"] = ext
		res["data"] = hex.EncodeToString(resp.Data)
		res["ok"] = true
		return true, 0
	}
	switch op {
	case "list-identity":
		it, err := c.ListIdentity(ctx)
		if err != nil {
			return fail(err)
		}
		res["identity"] = identityDoc(it.Identity, it.Socket.AddrPort().String())
		res["ok"] = true
	case "list-services":
		svcs, err := c.ListServices(ctx)
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, s := range svcs {
			out = append(out, map[string]any{"name": s.Name, "version": s.Version, "capabilities": s.Capabilities})
		}
		res["services"] = out
		res["ok"] = true
	case "get-attribute", "get-attributes-all", "set-attribute":
		req := cip.Request{Service: cip.ServiceGetAttributeSingle, Path: cip.AttributePath(cip.Class(*class), uint32(*instance), uint16(*attribute))}
		switch op {
		case "get-attributes-all":
			req = cip.Request{Service: cip.ServiceGetAttributesAll, Path: cip.ObjectPath(cip.Class(*class), uint32(*instance))}
		case "set-attribute":
			b, err := hex.DecodeString(*data)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "--data:", err)
				return 2
			}
			req.Service, req.Data = cip.ServiceSetAttributeSingle, b
		}
		resp, err := d.Do(ctx, req)
		if ok, code := status(resp, err); !ok {
			return code
		}
	case "multiple-get":
		var reqs []cip.Request
		for _, p := range paths {
			path, err := cip.ParsePath(p)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, err)
				return 2
			}
			reqs = append(reqs, cip.Request{Service: cip.ServiceGetAttributeSingle, Path: path})
		}
		type multi interface {
			MultipleService(context.Context, []cip.Request) ([]cip.Response, error)
		}
		resps, err := d.(multi).MultipleService(ctx, reqs)
		if err != nil {
			var ce *ethernetip.CIPError
			if errors.As(err, &ce) {
				res["status"], res["ok"] = int(ce.Status), true
				break
			}
			return fail(err)
		}
		var out []map[string]any
		for _, r := range resps {
			out = append(out, map[string]any{"status": int(r.Status), "data": hex.EncodeToString(r.Data)})
		}
		res["status"], res["replies"], res["ok"] = 0, out, true
	case "io":
		return ioOp(ctx, c, res, write, fail, scanner.IOConfig{
			ConfigInstance: uint32(*cfgInst), OutputInstance: uint32(*outInst), InputInstance: uint32(*inInst),
			OutputSize: *outSize, InputSize: *inSize, RPI: time.Duration(*rpi) * time.Millisecond,
			Large: *large, Multicast: *multicast,
		}, *outData, time.Duration(*dur)*time.Millisecond)
	case "read-tag":
		v, err := logix.NewClient(d, logix.WithMaxData(maxData(*connected, *large))).Read(ctx, *tag, *count)
		var ce *ethernetip.CIPError
		if err != nil && !errors.As(err, &ce) {
			return fail(err)
		}
		if ce != nil {
			res["status"], res["ok"] = int(ce.Status), true
			break
		}
		res["status"], res["type"], res["values"], res["ok"] = 0, v.Type.String(), valuesOf(v), true
	case "write-tag":
		t, ok := cip.ParseDataType(*typ)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "--type")
			return 2
		}
		v, err := parseValues(t, *values)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
		err = logix.NewClient(d, logix.WithMaxData(maxData(*connected, *large))).Write(ctx, *tag, v)
		var ce *ethernetip.CIPError
		if err != nil && !errors.As(err, &ce) {
			return fail(err)
		}
		res["status"], res["ok"] = 0, true
		if ce != nil {
			res["status"] = int(ce.Status)
		}
	case "tag-list":
		tags, err := logix.NewClient(d).ListTags(ctx, "")
		if err != nil {
			return fail(err)
		}
		var out []map[string]any
		for _, t := range tags {
			out = append(out, map[string]any{"name": t.Name, "type": t.Type.String(), "dims": t.Dims[:t.Type.Dims()]})
		}
		res["tags"], res["ok"] = out, true
	default:
		_, _ = fmt.Fprintf(stderr, "unknown operation %q\n", op)
		return 2
	}
	return write(0)
}

func maxData(connected, large bool) int {
	switch {
	case connected && large:
		return 3900
	case connected:
		return 450
	}
	return 480
}

func ioOp(ctx context.Context, c *client.Client, res result, write func(int) int, fail func(error) int, cfg scanner.IOConfig, outHex string, dur time.Duration) int {
	out, err := hex.DecodeString(outHex)
	if err != nil || (len(out) != 0 && len(out) != cfg.OutputSize) {
		res["error"] = opError{"usage", "--output-data must be output-size octets of hex"}
		return write(2)
	}
	s, err := scanner.New(c, scanner.WithLocalAddr(":2222"))
	if err != nil {
		return fail(err)
	}
	defer func() { _ = s.Close(ctx) }()
	var first []byte
	received := 0
	cfg.OnInput = func(data []byte, _ bool) {
		if first == nil {
			first = append([]byte(nil), data...)
		}
		received++
	}
	io, err := s.Open(ctx, cfg)
	fo := map[string]any{"status": 0, "extendedStatus": []int{}}
	if err != nil {
		var ce *ethernetip.CIPError
		if !errors.As(err, &ce) {
			return fail(err)
		}
		ext := []int{}
		for _, x := range ce.Extended {
			ext = append(ext, int(x))
		}
		fo["status"], fo["extendedStatus"] = int(ce.Status), ext
		res["forwardOpen"], res["ok"] = fo, true
		return write(0)
	}
	info := io.Info()
	fo["otConnectionId"], fo["toConnectionId"] = info.OTConnID, info.TOConnID
	fo["otApiUs"], fo["toApiUs"] = info.OTRPI.Microseconds(), info.TORPI.Microseconds()
	res["forwardOpen"] = fo
	if len(out) > 0 {
		_ = io.SetOutput(out)
	}
	select {
	case <-time.After(dur):
	case <-io.Done():
	}
	st := io.Stats()
	last, _, _ := io.Input()
	res["sent"], res["received"] = st.Sent, received
	res["firstInput"], res["lastInput"] = hex.EncodeToString(first), hex.EncodeToString(last)
	res["timedOut"] = io.State() == ethernetip.StateTimedOut
	fc := map[string]any{"status": 0}
	if err := io.Close(ctx); err != nil {
		var ce *ethernetip.CIPError
		if errors.As(err, &ce) {
			fc["status"] = int(ce.Status)
		} else {
			fc["error"] = err.Error()
		}
	}
	res["forwardClose"], res["ok"] = fc, true
	return write(0)
}

func identityDoc(id cip.Identity, socket string) map[string]any {
	return map[string]any{
		"vendorId": id.VendorID, "deviceType": uint16(id.DeviceType), "productCode": id.ProductCode,
		"revision": id.Revision.String(), "status": uint16(id.Status), "serialNumber": id.SerialNumber,
		"productName": id.ProductName, "state": id.State, "socketAddress": socket,
	}
}

func valuesOf(v logix.Value) []any {
	out := []any{}
	for i := 0; i < v.Count; i++ {
		switch {
		case v.Type.IsFloat():
			f, _ := v.Float(i)
			out = append(out, f)
		case v.Type == cip.TypeBOOL:
			b, _ := v.Bool(i)
			out = append(out, b)
		default:
			n, err := v.Int(i)
			if err != nil {
				return out
			}
			out = append(out, n)
		}
	}
	return out
}

func parseValues(t cip.DataType, s string) (logix.Value, error) {
	parts := strings.Split(s, ",")
	if t.IsFloat() {
		fs := make([]float64, len(parts))
		for i, p := range parts {
			f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil {
				return logix.Value{}, err
			}
			fs[i] = f
		}
		return logix.Floats(t, fs...)
	}
	is := make([]int64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseInt(strings.TrimSpace(p), 0, 64)
		if err != nil {
			return logix.Value{}, err
		}
		is[i] = n
	}
	return logix.Ints(t, is...)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }
