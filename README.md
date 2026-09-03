# keyfactor

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/keyfactor.svg)](https://pkg.go.dev/github.com/go-authn/keyfactor)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/keyfactor/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/keyfactor/actions/workflows/ci.yml)

Turns a security key into a factor a policy can ask. Pure Go, `CGO_ENABLED=0`,
no platform.

```go
f := keyfactor.New(linuxfido.Transport, keyfactor.Options{
    RPID:         "example.test",
    CredentialID: id,
})
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2}, somethingElse, f)
```

It is the piece between [go-authn/fido](https://github.com/go-authn/fido),
which speaks CTAP and knows about no operating system, and
[go-authn/mfa](https://github.com/go-authn/mfa), which decides how much proof is
enough and knows about no device. Neither should import the other.

## Why it is not in a platform package

It was, twice — once for macOS and once, nearly, for Linux. The two copies
differed in **one line**: which transport to open. Everything else — the
assertion, the flag checks, the refusal to spend somebody's last PIN attempt —
is the same everywhere CTAP is, which is everywhere.

So the platform package supplies an `Opener` and keeps what is genuinely
platform-specific: how a key is found, and what it means when there is none.

## What it refuses to confuse

- **A key answering is not a person being there.** The `UP` flag is checked, and
  `UV` when a PIN was used. A request for verification is not proof of it: a key
  may be asked and simply not do it.
- **A PIN is not a second factor.** The kind stays `Possession`. A PIN entered
  *into the key* never reaches this machine and identifies nobody to us — it
  protects the key. Counting it would let one object masquerade as two.
- **The last PIN attempt is not spent on a guess.** A wrong PIN costs a retry, a
  key that runs out locks until it is unplugged and then permanently, taking
  every credential on it. The count is asked for first, and a key that will not
  say is refused rather than tried.
- **An empty port is not a refusal.** The `Opener` decides — it is the only
  thing that knows — and its verdict is passed through untouched.
- **The challenge is random.** Nothing here verifies the signature, so there is
  no protocol to bind one to, and a fixed challenge would let a recorded
  assertion be replayed here for ever.

## Covered to 100%, with no key

The tests fake **the authenticator**, not the transport: a CTAPHID handshake, a
CTAP2 assertion, and a real ClientPIN exchange, built out of `go-authn/fido`'s
own exported framing. Stopping at the wire would have left everything this
package does untested.

⭐ The PIN half plays **the authenticator's side of protocol two independently**
— its own ECDH, its own HKDF, its own AES-CBC, written from the specification
rather than from the code under test. If the two derivations disagreed by a byte
the exchange would fail. A fake that reused the implementation would agree with
it for free, including when both were wrong.
