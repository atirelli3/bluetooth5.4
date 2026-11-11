# bt54: a Bluetooth LE security lab

[![CI](https://github.com/atirelli3/bluetooth5.4/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/atirelli3/bluetooth5.4/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/atirelli3/bluetooth5.4/main/pyproject.toml)](pyproject.toml)

A Python simulation lab for **Bluetooth LE security** (Core Specification v5.4): the cryptographic toolbox, LE Secure
Connections pairing (Just Works, Numeric Comparison; Legacy Pairing only as the `c1` and `s1` functions), AES-CCM,
Encrypted Advertising Data, and attacks on them (man in the middle, KNOB). Each attack is a command-line scenario with a deterministic expected outcome and a penetration-test style
write-up. Everything runs against simulated devices and the specification's own sample data: **no radio, no real
devices**.

## Quick start

You need [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```bash
uv sync
uv run python -m bt54 all          # every scenario: expected vs actual, exit code 0 or 1
uv run python -m bt54 just-works-mitm
bash scripts/gate.sh               # lint, format, tests, branch coverage >= 95%
```

```
$ uv run python -m bt54 just-works-mitm
just-works-mitm
  Eve read: secret LE data
  expected: paired with both victims; Eve reads and relays the packet
  actual:   paired with both victims; Eve reads and relays the packet
  PASS
```

## Scenarios

| Scenario | What it shows | Write-up |
|---|---|---|
| `just-works` | an honest Just Works pairing, then an encrypted packet | [pairing](docs/pairing.md) |
| `just-works-mitm` | Eve pairs with both victims and reads the traffic, undetected | [Just Works MitM](docs/attacks/just-works-mitm.md) |
| `numeric-comparison` | an honest Numeric Comparison pairing | [pairing](docs/pairing.md) |
| `numeric-comparison-mitm` | the same attack is caught when the users compare the numbers | [Numeric Comparison MitM](docs/attacks/numeric-comparison-mitm.md) |
| `numeric-comparison-mitm-blind` | and succeeds when the users accept without comparing | [Numeric Comparison MitM](docs/attacks/numeric-comparison-mitm.md) |
| `knob-bredr` | BR/EDR key size negotiated down to 1 octet: at most 256 trials recover the key | [KNOB](docs/attacks/knob.md) |
| `knob-le` | the LE floor of 7 octets: a 1-octet offer is refused, and 2^56 trials are priced | [KNOB](docs/attacks/knob.md) |
| `ead` | a key holder reads an Encrypted Advertising Data packet a keyless scanner cannot | [EAD](docs/ead.md) |

## What is inside

| Module | What it does |
|---|---|
| `src/bt54/toolbox.py` | the Security Manager functions `e`, AES-CMAC, `c1`, `s1`, `f4`, `f5`, `f6`, `g2`, `h6`, `h7` |
| `src/bt54/ccm.py` | AES-CCM written out for study, plus the LE link-layer nonce and AAD |
| `src/bt54/device.py` | a simulated device: P-256 key pair, ECDH with the peer-key checks, IO capability, `AuthReq` |
| `src/bt54/pairing.py` | LE Secure Connections: key size, stage 1 and 2, typed `PairingFailed` errors |
| `src/bt54/ead.py` | Encrypted Advertising Data: build and open the Randomizer/Payload/MIC AD data |
| `src/bt54/__main__.py` | the scenario command line |

**Correctness comes first.** No primitive counts as done until a test checks it against the specification's sample
data: Vol 3 Part H Appendix D, the `c1` and `s1` examples, Vol 6 Part C (session key and CCM packets) and the
Encrypted Data sample sets of CSS v11. The hand-rolled CCM is also checked against the `cryptography` library, and
the tests were spot-checked with hand-written mutants: deliberately broken code must make a test fail. The CI gate runs lint, format and
the tests with at least 95% branch coverage on Python 3.12 and 3.13. Dependabot and a weekly `pip-audit` of the
lockfile watch the supply chain.

## Encrypted Advertising Data and CCM, in short

Advertising packets are public. Core 5.4 added an *Encrypted Data* AD type: a 5-octet Randomizer, the encrypted AD
structures and a 4-octet MIC, protected by the same AES-CCM as the LE link layer. The Randomizer plays the role of
the packet counter in the nonce, and the two devices share one 16-octet session key and one 8-octet IV, which the
receiver reads from a GATT characteristic over an authenticated link. CCM authenticates with CBC-MAC and then
encrypts with CTR under a single key, and that is safe, so no second key is needed. `bt54` implements the format
in `src/bt54/ead.py`, verified against the specification's sample data. Details: [CCM](docs/ccm.md),
[EAD](docs/ead.md).

## Documentation

- [LE pairing](docs/pairing.md): feature exchange, method selection, Secure Connections, Legacy, key size
- [AES-CCM](docs/ccm.md) and [Encrypted Advertising Data](docs/ead.md)
- Attacks: [Just Works MitM](docs/attacks/just-works-mitm.md),
  [Numeric Comparison MitM](docs/attacks/numeric-comparison-mitm.md), [KNOB](docs/attacks/knob.md)
- [References](docs/references.md); the original 2024 slides are in [docs/cpa.pdf](docs/cpa.pdf) (Italian)

## Roadmap

Next: simulate each device's own view of the protocol messages, the Encrypted Advertising Data misuse cases, and
more attacks, one at a time with a scenario and a write-up each: Method Confusion, BLURtooth (cross-transport key
derivation), the Legacy TK brute force, and the LE key size downgrade.

## Responsible use

Everything in this repository is a simulation: devices, pairings and attacks run in Python against simulated peers
and the Bluetooth Core Specification's sample data. No code talks to a radio or to a real device. The attack
scenarios exist to study and explain the weaknesses and their fixes; do not use them against devices you do not own
or are not authorised to test.

## About

By Andrea Tirelli. It started as the exam project of *Crittografia Applicata* (2024) and grew into this lab.
Released under the [MIT licence](LICENSE).
