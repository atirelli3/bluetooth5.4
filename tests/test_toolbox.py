"""Security Manager toolbox against the spec's sample data (Core v5.4 Vol 3 Part H §2.2, Appendix D)."""

import pytest

from bt54.toolbox import aes_cmac, c1, e, f4, f5, f6, g2, h6, h7, s1


def h(text: str) -> bytes:
    """Hex as printed in the spec (spaces allowed) to bytes."""
    return bytes.fromhex(text.replace(" ", ""))


def salt(key_id: str) -> bytes:
    """128-bit SALT for h7: the 4 ASCII octets of key_id, zero-padded on the left (Appendix D.8)."""
    return bytes(12) + key_id.encode()


RFC4493_KEY = h("2b7e1516 28aed2a6 abf71588 09cf4f3c")
RFC4493_MSG = h(
    "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
    "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710"
)
U = h("20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6")
V = h("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd")
N1 = h("d5cb8454 d177733e ffffb2ec 712baeab")
N2 = h("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf")
DHKEY = h("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698")
A1 = h("00561237 37bfce")
A2 = h("00a71370 2dcfc1")
MAC_KEY = h("2965f176 a1084a02 fd3f6a20 ce636e20")
LTK = h("69867911 69d7cd23 980522b5 94750a38")
H6_H7_KEY = h("ec0234a3 57c8ad05 341010a6 0a397d9b")
CT_LTK = h("368df9bc e3264b58 bd066c33 334fbf64")
CT_LINK_KEY = h("05040302 01000908 07060504 03020100")


@pytest.mark.parametrize(
    ("length", "mac"),
    [
        pytest.param(0, "bb1d6929 e9593728 7fa37d12 9b756746", id="D.1.1"),
        pytest.param(16, "070a16b4 6b4d4144 f79bdd9d d04a287c", id="D.1.2"),
        pytest.param(40, "dfa66747 de9ae630 30ca3261 1497c827", id="D.1.3"),
        pytest.param(64, "51f0bebf 7e3b9d92 fc497417 79363cfe", id="D.1.4"),
    ],
)
def test_aes_cmac_matches_rfc4493(length, mac):
    assert aes_cmac(RFC4493_KEY, RFC4493_MSG[:length]) == h(mac)


def test_e_derives_the_le_session_key():
    """Vol 6 Part C §1: SK = e(LTK, SKD) with SKD = SKD_P || SKD_C, MSO first."""
    ltk = h("4C68384139F574D836BCF34E9DFB01BF")
    skd = h("0213243546576879acbdcedfe0f10213")
    assert e(ltk, skd) == h("99ad1b5226a37e3e058e3b8e27c2c666")


def test_c1_matches_spec_example():
    """§2.2.3 example."""
    confirm = c1(
        k=bytes(16),
        r=h("5783D52156AD6F0E6388274EC6702EE0"),
        preq=h("07071000000101"),
        pres=h("05000800000302"),
        iat=1,
        rat=0,
        ia=h("A1A2A3A4A5A6"),
        ra=h("B1B2B3B4B5B6"),
    )
    assert confirm == h("1E1E3FEF878988EAD2A74DC5BEF13B86")


def test_s1_matches_spec_example():
    """§2.2.4 example."""
    r1 = h("000F0E0D0C0B0A091122334455667788")
    r2 = h("010203040506070899AABBCCDDEEFF00")
    assert s1(bytes(16), r1, r2) == h("9a1fe1f0e8b0f49b5b4216ae796da062")


def test_f4_matches_d2():
    assert f4(U, V, N1, b"\x00") == h("f2c916f1 07a9bd1c f1eda1be a974872d")


def test_f5_matches_d3():
    assert f5(DHKEY, N1, N2, A1, A2) == (MAC_KEY, LTK)


def test_f6_matches_d4():
    r = h("12a3343b b453bb54 08da42d2 0c2d0fc8")
    check = f6(MAC_KEY, N1, N2, r, h("010102"), A1, A2)
    assert check == h("e3c47398 9cd0e8c5 d26c0b09 da958f61")


def test_g2_returns_the_32_bit_value_of_d5():
    assert g2(U, V, N1, N2) == 0x2F9ED5BA


def test_h6_matches_d6():
    assert h6(H6_H7_KEY, "lebr") == h("2d9ae102 e76dc91c e8d3a9e2 80b16399")


def test_h7_matches_d8():
    assert h7(salt("tmp1"), H6_H7_KEY) == h("fb173597 c6a3c0ec d2998c2a 75a57011")


@pytest.mark.parametrize(
    ("convert", "expected"),
    [
        pytest.param(
            lambda: h6(h7(salt("tmp1"), CT_LTK), "lebr"),
            "287ad379 dca40253 0a39f1f4 3047b835",
            id="D.9-ltk-to-link-key-ct2=1",
        ),
        pytest.param(
            lambda: h6(h6(CT_LTK, "tmp1"), "lebr"),
            "bc1ca4ef 633fc1bd 0d8230af ee388fb0",
            id="D.10-ltk-to-link-key-ct2=0",
        ),
        pytest.param(
            lambda: h6(h7(salt("tmp2"), CT_LINK_KEY), "brle"),
            "e85e09eb 5eccb3e2 69418a13 3211bc79",
            id="D.11-link-key-to-ltk-ct2=1",
        ),
        pytest.param(
            lambda: h6(h6(CT_LINK_KEY, "tmp2"), "brle"),
            "a813fb72 f1a3dfa1 8a2c9a43 f10d0a30",
            id="D.12-link-key-to-ltk-ct2=0",
        ),
    ],
)
def test_cross_transport_key_conversion(convert, expected):
    assert convert() == h(expected)


@pytest.mark.parametrize(
    ("call", "message"),
    [
        pytest.param(
            lambda: f4(U[:31], V, N1, b"\x00"), "U must be 32", id="f4-short-U"
        ),
        pytest.param(
            lambda: f5(DHKEY, N1, N2, A1[:6], A2), "A1 must be 7", id="f5-6-octet-A1"
        ),
        pytest.param(
            lambda: f6(MAC_KEY, N1, N2, N1, b"\x01", A1, A2),
            "IOcap must be 3",
            id="f6-short-IOcap",
        ),
        pytest.param(lambda: g2(U, V, N1, N2[:15]), "Y must be 16", id="g2-short-Y"),
        pytest.param(
            lambda: h6(H6_H7_KEY, "lebr2"), "keyID must be 4", id="h6-5-octet-keyID"
        ),
        pytest.param(
            lambda: h7(bytes(15), H6_H7_KEY), "SALT must be 16", id="h7-short-SALT"
        ),
        pytest.param(
            lambda: s1(bytes(16), bytes(16), bytes(8)),
            "r2 must be 16",
            id="s1-short-r2",
        ),
        pytest.param(
            lambda: c1(
                bytes(16), bytes(16), bytes(7), bytes(7), 0, 0, bytes(6), bytes(5)
            ),
            "ra must be 6",
            id="c1-short-ra",
        ),
        pytest.param(
            lambda: c1(
                bytes(16), bytes(16), bytes(7), bytes(7), 2, 0, bytes(6), bytes(6)
            ),
            "iat and rat must be 0 or 1",
            id="c1-address-type-2",
        ),
    ],
)
def test_bad_inputs_are_rejected(call, message):
    with pytest.raises(ValueError, match=message):
        call()
