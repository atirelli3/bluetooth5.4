# KNOB and the encryption key size floor

| | |
|---|---|
| Scenarios | `uv run python -m bt54 knob-bredr`, `uv run python -m bt54 knob-le` |
| Target | the encryption key size negotiation: BR/EDR (the KNOB attack) and LE (the 7-octet floor) |
| Class | active man in the middle on an unauthenticated negotiation, then offline brute force |
| CVE | [CVE-2019-9506](https://nvd.nist.gov/vuln/detail/cve-2019-9506), CERT/CC VU#918987 (BR/EDR) |
| Spec | Core v5.4 Vol 2 Part H §4.1, §9.4; Vol 2 Part C §4.2.5; Vol 3 Part H §2.3.4 |

## Summary

Two Bluetooth devices agree on how many octets of the session key are real. That agreement is not authenticated, so
an attacker in the middle can push both to a tiny key and then try every key. On BR/EDR the original paper
(Antonioli, Tippenhauer, Rasmussen, USENIX Security 2019) forced "only 1 byte (8 bits) of entropy": at most 256 trials.
On LE the specification sets a floor of 7 octets, so a 1-octet key is refused; the floor is still only 56 bits.

## Threat model

- Alice and Bob negotiate the key size for an encrypted link. **Eve** is an active attacker that relays and changes
  the negotiation messages, so both devices accept the small size.
- Eve records one encrypted packet. With a 1-octet key she tries the 256 possible keys offline and keeps the one
  whose MIC verifies. With the key she can also forge packets.

## Preconditions

1. The key size negotiation is not authenticated (it happens before encryption starts) and a device accepts a short key.
   BR/EDR: the specification allows `1 <= L_max <= 16` (Vol 2 Part H §4.1), although the LMP text says `L_max`
   shall be at least 7 octets and `L_min` should be (Vol 2 Part C §4.2.5); the paper found devices that agreed on 1.
2. Eve can modify the negotiation of a link being set up (jamming and relaying on a real radio).

## Proof of concept 1: `knob-bredr`

```
$ uv run python -m bt54 knob-bredr
knob-bredr
  session key (1 octet): 7c000000000000000000000000000000, found after 125 trials
  expected: key recovered
  actual:   key recovered
  PASS
```

The BR/EDR AES-CCM key reduction is the opposite of the LE one: the *least* significant octets are replaced with
`0x00` (Vol 2 Part H §9.4, `pairing.mask_key_bredr`). A 1-octet key is therefore one octet followed by 15 zero octets,
as printed above. The scenario encrypts one packet with it, then `_recover_key(..., bredr=True)` tries all 256 keys
of that form and keeps the one whose MIC verifies (at most 256 trials; with a 4-octet MIC a wrong key verifies with
probability about 2^-32 per trial). Only a tag failure counts as "wrong key": a bad parameter must raise, or the
loop would report "not found" and look like a successful defence.

## Proof of concept 2: `knob-le`

```
$ uv run python -m bt54 knob-le
knob-le
  2^56 trials (the 7-octet floor):
    hand-rolled CCM, one core                   40,518 trials/s  56,393 years
    AESCCM in a Python loop, one core          683,950 trials/s  3,341 years
    assumed attacker hardware           10,000,000,000 trials/s  83 days
  expected: pairing failed: ENCRYPTION_KEY_SIZE; 2^56 trials take 83 days at an assumed 10^10 trials/s
  actual:   pairing failed: ENCRYPTION_KEY_SIZE; 2^56 trials take 83 days at an assumed 10^10 trials/s
  PASS
```

On LE the maximum and minimum key sizes are between 7 and 16 octets, the shorter maximum wins, and a device sends
Pairing Failed *Encryption Key Size* (0x06) if the result is below its own minimum (Vol 3 Part H §2.3.4). So the
scenario shows a device offering 1 octet being **refused**. It then prices the search at the floor.

**Read the table with care.** The first two rows are measured on the machine that runs the scenario and are only
printed: the hand-rolled CCM is written for study, and the library AESCCM is called from a Python loop, so both are far
slower than an attacker's code. The third row is an **assumption** (10^10 trials/s, hardware or a cluster), not a
measurement; the verdict rests on it. At that rate 2^56 trials take 83 days, and one more order of magnitude makes it
8 days. **Seven octets is the specification's floor, not a strong key.**

## Impact

BR/EDR: the attacker recovers the session key of an encrypted link in 256 trials, then reads and forges traffic.
LE: a 56-bit key is within reach of a determined attacker, and a downgrade to 7 octets of an LE link has been
reported (Antonioli et al., ACM TOPS 2020: LE Secure Connections devices also ended with 7-octet keys, because the key
size field of the pairing is not authenticated). Neither `f5` nor `f6` takes the key size as input.

## Mitigation and detection

- **Set a high minimum.** Each device has a minimum key size parameter, defined by a profile or the application
  (§2.3.4); use 16 octets for anything that matters. For BR/EDR, `HCI_Set_Min_Encryption_Key_Size` (Vol 4 Part E
  §7.3.102, optional, since 5.3) makes the Controller refuse a smaller key. The SIG recommends at least 7 octets for
  BR/EDR connections.
- **Refuse short keys** and treat a failed negotiation as a signal (Pairing Failed 0x06).
- Use Secure Connections with AES-CCM where possible; the key size still has to be enforced.

## Limits of the simulation

- The negotiation messages are not simulated (no LMP, no relay of `LMP_encryption_key_size_req`): the scenarios start
  after the size is agreed.
- BR/EDR E0, the encryption of legacy and Secure Simple Pairing links, reduces its key with a polynomial operation
  (Vol 2 Part H §4.5), not by zeroing octets; only the AES-CCM reduction (§9.4) is modelled. The packet framing reuses
  the LE nonce size and AAD.
- The text of §9.4 does not say whether the reduction is applied to the output of `h3` or at another step.
- The LE downgrade (the key size field changed during feature exchange) is a planned scenario.

## References

Core v5.4 Vol 2 Part H §4.1, §9.4; Vol 2 Part C §4.2.5; Vol 3 Part H §2.3.4; Vol 4 Part E §7.3.102. Antonioli,
Tippenhauer, Rasmussen, *The KNOB is Broken*, USENIX Security 2019, and the 2020 ACM TOPS extension; CVE-2019-9506;
the Bluetooth SIG statement on key negotiation ([references](../references.md)). Overview: [pairing](../pairing.md),
[ccm](../ccm.md).
