import pytest
from open_evidence.jcs import jcs_loads_strict, jcs_serialize, jcs_sha256


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
    ],
)
def test_normative_number_vectors(value, expected):
    assert jcs_serialize(value) == expected


def test_non_finite_numbers_reject():
    with pytest.raises(ValueError, match="NaN is not a finite"):
        jcs_serialize(float("nan"))
    with pytest.raises(ValueError, match="Infinity is not a finite"):
        jcs_serialize(float("inf"))
    with pytest.raises(ValueError, match="Infinity is not a finite"):
        jcs_serialize(float("-inf"))


def test_key_ordering_is_utf16():
    # RFC 8785 requires UTF-16 code-unit order.
    # "\u20ac" (Euro sign, 3-byte UTF-8, BMP) vs "\U0001d11e" (G-clef, 4-byte UTF-8, surrogate pair in UTF-16)
    data = {"\u20ac": 1, "\U0001d11e": 2, "a": 3}
    expected = b'{"a":3,"\xe2\x82\xac":1,"\xf0\x9d\x84\x9e":2}'
    assert jcs_serialize(data) == expected


def test_no_insignificant_whitespace():
    data = {"key": "value", "list": [1, 2, None, True, False]}
    serialized = jcs_serialize(data)
    assert b" " not in serialized
    assert b"\n" not in serialized


def test_string_escaping():
    data = {"quote": '"', "backslash": "\\", "newline": "\n", "tab": "\t"}
    serialized = jcs_serialize(data)
    assert serialized == b'{"backslash":"\\\\","newline":"\\n","quote":"\\"","tab":"\\t"}'


def test_duplicate_keys_rejected():
    with pytest.raises(ValueError, match="duplicate key"):
        jcs_loads_strict('{"a": 1, "a": 2}')


def test_sha256_deterministic():
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert jcs_sha256(obj1) == jcs_sha256(obj2)
