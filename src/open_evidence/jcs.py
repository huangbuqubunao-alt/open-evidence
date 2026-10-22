"""RFC 8785 JSON Canonicalization Scheme (JCS) Serializer and Strict Decoder.

This module provides a pure standard-library implementation of the RFC 8785
JSON Canonicalization Scheme (JCS).

Guarantees:
- Strict UTF-8 output without BOM.
- Lexicographic property name sorting based on UTF-16 code units.
- Strict ECMAScript (ECMA-262 Section 7.1.12.1) NumberToString semantics.
- Non-finite numbers (NaN, Infinity, -Infinity) are rejected.
- Negative zero (-0.0) serializes canonically as "0".
- Strict decoder rejects duplicate object keys and non-finite constants.
- No third-party dependencies required.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from decimal import Decimal
from typing import Final, NoReturn

__all__ = [
    "jcs_loads_strict",
    "jcs_serialize",
    "jcs_sha256",
]

_SHORT_CONTROL_ESCAPES: Final[dict[int, str]] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _format_number(value: int | float) -> str:
    """Format one finite JSON number exactly per ECMAScript ``NumberToString``.

    The input domain is finite IEEE-754 binary64-compatible JSON numbers.
    This is the single canonical number formatter.
    """
    if isinstance(value, bool):
        msg = "boolean is not a JSON number"
        raise ValueError(msg)

    if isinstance(value, int):
        number = float(value)
        if number.is_integer() and int(number) != value:
            msg = "integer exceeds the JCS binary64 numeric domain"
            raise ValueError(msg)
    else:
        number = value

    if math.isnan(number):
        msg = "NaN is not a finite JCS number"
        raise ValueError(msg)
    if math.isinf(number):
        msg = "Infinity is not a finite JCS number"
        raise ValueError(msg)
    if number == 0:
        return "0"

    sign = "-" if number < 0 else ""
    magnitude = abs(number)

    decimal = Decimal(repr(magnitude)).normalize()
    digits_tuple = decimal.as_tuple()
    digits = digits_tuple.digits
    exponent = digits_tuple.exponent
    if not isinstance(digits, tuple) or isinstance(exponent, str):
        msg = "unexpected decimal representation for a finite number"
        raise ValueError(msg)

    digit_count = len(digits)
    digit_string = "".join(str(digit) for digit in digits)
    decimal_point = exponent + digit_count

    if digit_count <= decimal_point <= 21:
        return sign + digit_string + "0" * (decimal_point - digit_count)
    if 0 < decimal_point <= 21:
        return sign + digit_string[:decimal_point] + "." + digit_string[decimal_point:]
    if -6 < decimal_point <= 0:
        return sign + "0." + "0" * (-decimal_point) + digit_string

    power = decimal_point - 1
    power_sign = "+" if power >= 0 else "-"
    mantissa = (
        digit_string
        if digit_count == 1
        else digit_string[0] + "." + digit_string[1:]
    )
    return sign + mantissa + "e" + power_sign + str(abs(power))


def _escape_string(value: str) -> str:
    """Serialize one string with RFC 8785 / ECMAScript escaping."""
    parts: list[str] = ['"']
    for character in value:
        code_point = ord(character)
        if character == '"':
            parts.append('\\"')
        elif character == "\\":
            parts.append("\\\\")
        elif code_point in _SHORT_CONTROL_ESCAPES:
            parts.append(_SHORT_CONTROL_ESCAPES[code_point])
        elif code_point < 0x20:
            parts.append(f"\\u{code_point:04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _serialize_value(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_number(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize_value(item) for item in value) + "]"
    if isinstance(value, dict):
        string_items: list[tuple[str, object]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                msg = "JCS object keys must be strings"
                raise ValueError(msg)
            string_items.append((key, item))
        # RFC 8785: sort by UTF-16 code-unit order of the property names.
        string_items.sort(key=lambda pair: pair[0].encode("utf-16-be"))
        body = ",".join(
            _escape_string(key) + ":" + _serialize_value(item)
            for key, item in string_items
        )
        return "{" + body + "}"
    msg = f"unsupported type for JCS serialization: {type(value).__name__}"
    raise ValueError(msg)


def jcs_serialize(value: object) -> bytes:
    """Serialize ``value`` to RFC 8785 Canonical JSON strict-UTF-8 bytes."""
    text = _serialize_value(value)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        msg = "JCS output must be strict UTF-8 (no unpaired surrogates)"
        raise ValueError(msg) from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in seen:
            msg = f"duplicate key in JSON object: {key!r}"
            raise ValueError(msg)
        seen.add(key)
        result[key] = item
    return result


def _reject_non_finite_constant(name: str) -> NoReturn:
    msg = f"non-finite JSON constant is not permitted in JCS: {name}"
    raise ValueError(msg)


_STRICT_PAIRS_HOOK: Final[Callable[[list[tuple[str, object]]], dict[str, object]]] = (
    _reject_duplicate_keys
)


def jcs_loads_strict(data: bytes | str) -> object:
    """Decode JSON strictly per RFC 8785, rejecting duplicate keys and non-finite numbers."""
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            msg = "JSON bytes must be strict UTF-8"
            raise ValueError(msg) from exc
    elif isinstance(data, str):
        text = data
    else:
        msg = f"JSON input must be bytes or str, got {type(data).__name__}"
        raise ValueError(msg)
    try:
        return json.loads(
            text,
            object_pairs_hook=_STRICT_PAIRS_HOOK,
            parse_constant=_reject_non_finite_constant,
        )
    except json.JSONDecodeError as exc:
        msg = f"JSON is malformed: {exc.msg}"
        raise ValueError(msg) from exc


def jcs_sha256(value: object) -> str:
    """Return the lowercase SHA-256 hex digest of the canonical bytes."""
    return hashlib.sha256(jcs_serialize(value)).hexdigest()
