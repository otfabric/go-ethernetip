# Contributing to go-ethernetip

Thank you for your interest in contributing to `go-ethernetip`!

## Getting Started

1. Fork the repository on GitHub and clone your fork:
   ```sh
   git clone git@github.com:<your-username>/go-ethernetip.git
   cd go-ethernetip
   ```
2. Create a feature branch: `git checkout -b feature/my-change`

## Development Setup

- Go 1.23+ (see [go.mod](go.mod)); the code must build and pass on Go 1.23,
  so do not use newer language or standard-library features
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/) v2 and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the checks
- No hardware and no simulator: the tests run the library's ends against each other over loopback
- Docker, for the interop tests only
- `make fmt` and `make fmt-check` run the gofmt of the Go version in go.mod, which Go downloads (`GOTOOLCHAIN`) on first use

```sh
make check        # everything CI checks
make test         # tests with the race detector
make coverage-check
make fuzz         # FUZZTIME=30s per target by default
make chaos stress
make generate     # after editing cip/catalog.json or eds/testdata/otfabric_adapter.eds
make interop      # needs Docker
```

## Guidelines

### Code

- **No dependencies** outside the standard library.
- **Codecs stay pure**: `cip`, `encap` and the codec of `implicit` do no I/O
  beyond `encap.ReadPacket` over an `io.Reader`.
- **Untrusted input**: every decoder checks lengths before slicing and
  counts before allocating; network input must never panic the process. A
  new decoder comes with a fuzz target.
- **Vendor extensions** (Rockwell Logix) stay in `logix`; codes go in the
  catalog marked `"vendor": true`.
- **Every exported symbol is documented**, comments end with a period
  (`godot`). Say which goroutine owns a field, and what a callback may do.
- **Errors** are sentinels wrapped with detail, or typed errors for the
  peer's answers; see [ERRORS.md](ERRORS.md).
- **Codes are a catalog**: `cip/catalog.json` (with its `source` per entry)
  and `cip/vendors.json` generate `cip/catalog_gen.go` and `CATALOG.md`
  (`internal/cmd/gencatalog`). Change the catalog and run `make generate`,
  never the generated files; CI fails when they drift. Add a source for
  every code you add; ODVA specification text is never copied.
- **The sample EDS** `eds/testdata/otfabric_adapter.eds` generates
  `eds/internal/sampledevice` (`internal/cmd/gensample`), checked the same
  way.

### Tests

| Change | Test |
|---|---|
| A codec | Known vectors, round trips, malformed input with the exact error; a fuzz target or seed |
| Server behaviour | A raw-socket or client test in `server` with the exact status |
| Client behaviour | A test against the server or a scripted peer |
| A feature across roles | An e2e test |
| Behaviour the references also have | An interop test in `interop/` |

Tests pass with `-race` repeatedly; no fixed sleeps to wait for something.

### Interop

The interop tests consume the images of
[otfabric/ethernetip-interop](https://github.com/otfabric/ethernetip-interop)
at the release pinned in `interop/harness_test.go` (`interopRelease`).
This repository holds no reference code. When a reference deviates, record
it in [docs/research/STACKS.md](docs/research/STACKS.md) and in the
test's note; a feature the reference lacks is `notApplicable`, never a
pass.

## Pull Requests

- One logical change per pull request, with what and why
- `make check` passes; `make interop` passes for protocol changes
- Add the change to [RELEASE.md](RELEASE.md) in the section of the next
  version and update the documents the change affects

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](LICENSE).
