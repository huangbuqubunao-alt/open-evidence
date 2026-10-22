import pytest

from open_evidence.jcs import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    jcs_loads_strict,
    jcs_serialize,
    jcs_sha256,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, b"0"),
        (-0.0, b"0"),
        (1, b"1"),
        (-1, b"-1"),
        (1.5, b"1.5"),
        (0.0000015, b"0.0000015"),
        (0.000001, b"0.000001"),
        (1e-7, b"1e-7"),
        (1e20, b"100000000000000000000"),
        (1e21, b"1e+21"),
        (-1e21, b"-1e+21"),
        (MAX_SAFE_INTEGER, str(MAX_SAFE_INTEGER).encode("ascii")),
        (MIN_SAFE_INTEGER, str(MIN_SAFE_INTEGER).encode("ascii")),
    ],
)
def test_normative_number_vectors(value: float, expected: bytes) -> None:
    assert jcs_serialize(value) == expected


def test_integer_safe_range_boundaries() -> None:
    # Exactly at boundary
    assert jcs_serialize(9007199254740991) == b"9007199254740991"
    assert jcs_serialize(-9007199254740991) == b"-9007199254740991"

    # Beyond boundary: must raise ValueError to prevent IEEE 754 precision loss
    with pytest.raises(ValueError, match="exceeds the I-JSON / IEEE-754 safe integer range"):
        jcs_serialize(9007199254740992)
    with pytest.raises(ValueError, match="exceeds the I-JSON / IEEE-754 safe integer range"):
        jcs_serialize(-9007199254740992)
    with pytest.raises(ValueError, match="exceeds the I-JSON / IEEE-754 safe integer range"):
        jcs_serialize(2**60)


def test_rfc8785_official_reference_vector() -> None:
    """Official test vector from RFC 8785 reference implementation (cyberphone/json-canonicalization)."""
    raw_input = """{
      "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
      "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/",
      "literals": [null, true, false]
    }"""
    parsed = jcs_loads_strict(raw_input)
    serialized = jcs_serialize(parsed)
    expected = (
        b'{"literals":[null,true,false],'
        b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/\"}'
    )
    assert serialized == expected


def test_non_finite_numbers_reject() -> None:
    with pytest.raises(ValueError, match="NaN is not a finite"):
        jcs_serialize(float("nan"))
    with pytest.raises(ValueError, match="Infinity is not a finite"):
        jcs_serialize(float("inf"))
    with pytest.raises(ValueError, match="Infinity is not a finite"):
        jcs_serialize(float("-inf"))


def test_key_ordering_is_utf16() -> None:
    # RFC 8785 requires UTF-16 code-unit order.
    # "\u20ac" (Euro sign, 3-byte UTF-8, BMP) vs "\U0001d11e" (G-clef, 4-byte UTF-8, surrogate pair in UTF-16)
    data = {"\u20ac": 1, "\U0001d11e": 2, "a": 3}
    expected = b'{"a":3,"\xe2\x82\xac":1,"\xf0\x9d\x84\x9e":2}'
    assert jcs_serialize(data) == expected


def test_key_with_unpaired_surrogate_rejected() -> None:
    with pytest.raises(ValueError, match="unpaired surrogates"):
        jcs_serialize({"\ud800": "value"})


def test_value_with_unpaired_surrogate_rejected() -> None:
    with pytest.raises(ValueError, match="unpaired surrogates"):
        jcs_serialize({"key": "\ud800"})


def test_no_insignificant_whitespace() -> None:
    data = {"key": "value", "list": [1, 2, None, True, False]}
    serialized = jcs_serialize(data)
    assert b" " not in serialized
    assert b"\n" not in serialized


def test_string_escaping() -> None:
    data = {"quote": '"', "backslash": "\\", "newline": "\n", "tab": "\t"}
    serialized = jcs_serialize(data)
    assert serialized == b'{"backslash":"\\\\","newline":"\\n","quote":"\\"","tab":"\\t"}'


def test_duplicate_keys_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate key"):
        jcs_loads_strict('{"a": 1, "a": 2}')


def test_sha256_deterministic() -> None:
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert jcs_sha256(obj1) == jcs_sha256(obj2)


def test_jcs_loads_strict_rejects_inf_and_nan_numbers() -> None:
    with pytest.raises(ValueError, match="non-finite JSON number out of IEEE 754 range"):
        jcs_loads_strict("1e999")
    with pytest.raises(ValueError, match="non-finite JSON number out of IEEE 754 range"):
        jcs_loads_strict("-1e999")
    with pytest.raises(ValueError, match="non-finite JSON constant"):
        jcs_loads_strict("NaN")
    with pytest.raises(ValueError, match="non-finite JSON constant"):
        jcs_loads_strict("Infinity")


def test_jcs_loads_strict_rejects_out_of_range_integers() -> None:
    with pytest.raises(ValueError, match="exceeds I-JSON / IEEE-754 safe integer range"):
        jcs_loads_strict("9007199254740992")
    with pytest.raises(ValueError, match="exceeds I-JSON / IEEE-754 safe integer range"):
        jcs_loads_strict("-9007199254740992")
    with pytest.raises(ValueError, match="exceeds I-JSON / IEEE-754 safe integer range"):
        jcs_loads_strict("1000000000000000000000000000000")


def test_jcs_loads_strict_rejects_unpaired_surrogates() -> None:
    with pytest.raises(ValueError, match="unpaired surrogates"):
        jcs_loads_strict('"\\ud800"')
    with pytest.raises(ValueError, match="unpaired surrogates"):
        jcs_loads_strict('{"\\ud800": "val"}')
