# AES-CCM in Bluetooth LE

CCM (Counter with CBC-MAC, [RFC 3610](https://www.rfc-editor.org/info/rfc3610), NIST SP 800-38C) is an authenticated
encryption mode for a 128-bit block cipher. Bluetooth LE uses it with AES-128 to encrypt and authenticate every
data packet after pairing (Core v5.4 Vol 6 Part E §1), and Encrypted Advertising Data uses the same algorithm
([EAD](ead.md)). Code: `src/bt54/ccm.py`, a hand-rolled version written out for study and checked against the
specification's sample packets and against the `cryptography` library.

## 1. What CCM does

Input: a key, a nonce, the payload to encrypt and *additional authenticated data* (AAD, authenticated but sent in the
clear). Output: the encrypted payload followed by a MIC (message integrity code, the authentication tag).
CCM is **authenticate-then-encrypt**: the tag is computed over the plaintext first, then everything is encrypted.

1. **Authenticate (CBC-MAC).** Build a block `B0` (flags, nonce, payload length), then the AAD (its length, the AAD,
   zero padding), then the payload (zero padded). Run AES in CBC mode over these blocks with a zero start vector.
   The first `M` octets of the last output block are the tag `T`. (`ccm._mac`)
2. **Encrypt (CTR).** The counter blocks are `A_i = flags || nonce || i`. Encrypt the payload by XOR with the AES
   output of `A_1, A_2, ...`, and encrypt the tag by XOR with the AES output of `A_0`. (`ccm._ctr`, `ccm.encrypt`)
3. **Decrypt.** Reverse step 2, recompute the tag from the recovered plaintext and compare it to the received one;
   a mismatch means the key, nonce, AAD or data is wrong. The comparison is constant time (`hmac.compare_digest`).

### One key is enough

CBC-MAC and CTR both use the *same* AES key, and that is safe: the first block of the MAC input starts with the
flags of `B0`, the counter blocks carry different flags, so the two never encrypt the same block. The combination has
a security analysis (Jonsson, "On the Security of CTR + CBC-MAC", SAC 2002; see [references](references.md)). The Link Layer therefore needs
only one session key, derived once per encryption start; this is a property of CCM, not a limit of Bluetooth.
Authenticate-then-encrypt is acceptable here because the MAC is checked before any plaintext is used and a failure
ends the connection.

## 2. The LE parameters (Vol 6 Part E)

| Parameter | Value |
|---|---|
| Block cipher | AES-128 |
| `M` (MIC size) | 4 octets |
| `L` (length field size) | 2 octets, so the nonce is 13 octets |
| Session key | `SK = e(LTK, SKD)` with `SKD = SKD_P || SKD_C` (Vol 6 Part B §5.1.3.1, `toolbox.e`) |
| IV | 8 octets, `IV = IV_P || IV_C`, exchanged when encryption starts |

**Nonce** (Table 2.1, `ccm.ll_nonce`): 13 octets, least significant octet first: the 39-bit `packetCounter`, then the
1-bit `directionBit` (1 for packets sent by the Central, 0 for the Peripheral) in the top bit of octet 4, then the IV.
**AAD** (Table 2.3, `ccm.ll_aad`): the first octet of the packet header with the NESN, SN and MD bits set to 0.
The specification gives no reason; these are the acknowledgement, sequence and more-data bits of the header, which
can differ between two transmissions of the same packet.

Worked example (Vol 6 Part C sample data, `tests/test_ccm.py`): session key `99ad1b5226a37e3e058e3b8e27c2c666`,
IV `DEAFBABEBADCAB24`, the first packet the Central sends, `LL_START_ENC_RSP`:

| Item | Value |
|---|---|
| counter 0, direction 1 | nonce `000000008024abdcbabebaafde` |
| header octet | `03` |
| payload | `06` |
| encrypted payload + MIC | `9f` + `cda7f448` |

## 3. What the nonce prevents

A (key, nonce) pair must never encrypt two packets: CTR would reuse its keystream and the XOR of the two ciphertexts
equals the XOR of the plaintexts. The nonce guards against this and against two other replays:

- **Replay.** The same packet sent again carries the old counter; the receiver expects the next one and the MIC
  fails. (`test_a_replayed_packet_fails_at_the_next_counter`)
- **Reflection.** A packet sent back to its sender has the wrong `directionBit`, so its MIC fails.
  (`test_a_reflected_packet_fails_in_the_other_direction`)
- **Tampering.** Any change to the ciphertext, the MIC, the AAD, the nonce or the key fails the MIC; the
  connection is then considered lost (error 0x3D, *Connection Terminated due to MIC Failure*).

A short key is the other weakness: with a 1-octet key 256 trials recover it; see [KNOB](attacks/knob.md).

## 4. How the code is checked

- the four sample packets of Vol 6 Part C (encrypt and decrypt);
- parity with `cryptography`'s `AESCCM` over nonce sizes 7, 10, 13, tag sizes 4, 10, 16, several AAD and payload
  sizes;
- tamper tests for every input, and for bad parameters;
- a brute-force loop must catch the tag failure only, never a bad parameter, or it would report "key not found"
  for a wrong-sized key.
