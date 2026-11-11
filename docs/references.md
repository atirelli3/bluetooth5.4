# References

Every claim in these docs cites a section of the Bluetooth specification or one of the sources below. The
specification is the source of truth; the sample data it contains is what the tests check.

## Bluetooth specifications

All Core v5.4 pages are under
`https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/`
([index](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/index-en.html)).

| Topic | Where |
|---|---|
| Security Manager: pairing, key generation, toolbox, sample data (Vol 3 Part H) | [host/security-manager-specification.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html) |
| LE Link Layer security, CCM (Vol 6 Part E); sample data (Vol 6 Part C) | [low-energy-controller/low-energy-link-layer-security.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/low-energy-link-layer-security.html) |
| Link Layer: encryption start, PAwR (Vol 6 Part B) | [low-energy-controller/link-layer-specification.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html) |
| GAP: Encrypted Data Key Material (Vol 3 Part C §12.6) | [host/generic-access-profile.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-access-profile.html) |
| BR/EDR security: key size, AES-CCM (Vol 2 Part H) | [br-edr-controller/security-specification.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/br-edr-controller/security-specification.html) |
| BR/EDR LMP: key size negotiation (Vol 2 Part C) | [br-edr-controller/link-manager-protocol-specification.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/br-edr-controller/link-manager-protocol-specification.html) |
| Encrypted Data AD type, sample data (CSS v11 Part A §1.23, §2.3) | [data-types-specification.html](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v11/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html) |
| What is new in 5.4 (EAD, PAwR) | [SIG overview](https://www.bluetooth.com/bluetooth-resources/whats-new-in-bluetooth-core-5-4-an-overview/), [5.4 technical overview (PDF)](https://www.bluetooth.com/wp-content/uploads/2023/02/2301_5.4_Tech_Overview_FINAL.pdf) |
| Electronic Shelf Label, built on PAwR, commands protected through EAD | [SIG blog](https://www.bluetooth.com/blog/bluetooth-esl-the-global-standard-for-the-electronic-shelf-label-market/) |

## CCM

- Whiting, Housley, Ferguson. *Counter with CBC-MAC (CCM)*. [RFC 3610](https://www.rfc-editor.org/info/rfc3610), 2003.
- Dworkin. *Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality*.
  [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final), 2004, updated 2007.
- Jonsson. *On the Security of CTR + CBC-MAC*. Selected Areas in Cryptography (SAC 2002), LNCS 2595, pp. 76-93,
  Springer, 2002 (security bounds for CCM in terms of the block cipher):
  [doi:10.1007/3-540-36492-7_7](https://link.springer.com/chapter/10.1007/3-540-36492-7_7).

## Attacks and advisories

- **KNOB.** Antonioli, Tippenhauer, Rasmussen. *The KNOB is Broken: Exploiting Low Entropy in the Encryption Key
  Negotiation Of Bluetooth BR/EDR*. USENIX Security 2019, pp. 1047-1061.
  [usenix.org](https://www.usenix.org/conference/usenixsecurity19/presentation/antonioli).
  [CVE-2019-9506](https://nvd.nist.gov/vuln/detail/cve-2019-9506),
  [CERT/CC VU#918987](https://www.kb.cert.org/vuls/id/918987),
  [Bluetooth SIG statement](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/statement-key-negotiation-of-bluetooth/).
- **Downgrade attacks on BR/EDR and LE.** Antonioli, Tippenhauer, Rasmussen. *Key Negotiation Downgrade Attacks on
  Bluetooth and Bluetooth Low Energy*. ACM Transactions on Privacy and Security 23(3), article 14, 2020.
  [doi:10.1145/3394497](https://doi.org/10.1145/3394497).
- **Method Confusion.** von Tschirschnitz, Peuckert, Franzen, Großklags. *Method Confusion Attack on Bluetooth
  Pairing*. IEEE S&P 2021. [doi:10.1109/SP40001.2021.00013](https://doi.org/10.1109/SP40001.2021.00013);
  [SIG statement](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/method-vulnerability/).
- **Invalid curve attack on pairing.** [CVE-2018-5383](https://nvd.nist.gov/vuln/detail/cve-2018-5383),
  [CERT/CC VU#304725](https://www.kb.cert.org/vuls/id/304725): implementations that do not validate the elliptic curve
  parameters of a received public key.
- **BLURtooth.** [CVE-2020-15802](https://nvd.nist.gov/vuln/detail/cve-2020-15802),
  [CERT/CC VU#589825](https://www.kb.cert.org/vuls/id/589825).
- **crackle** (LE Legacy TK brute force, Mike Ryan): [github.com/mikeryan/crackle](https://github.com/mikeryan/crackle).

## Background

- NIST. *Guide to Bluetooth Security*, SP 800-121 Rev. 2 Update 1:
  [nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-121r2-upd1.pdf).
- *Understanding Bluetooth LE Pairing, Step by Step*, All About Circuits:
  [allaboutcircuits.com](https://www.allaboutcircuits.com/technical-articles/understanding-bluetooth-le-pairingstep-by-step/).

The 2024 slides of the exam project this repository started from are in [`cpa.pdf`](cpa.pdf) (Italian, archive).
