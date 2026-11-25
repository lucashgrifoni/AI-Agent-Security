"""Make text from an untrusted source safe to print to a terminal or a log.

A target, an MCP server or a tool definition can put terminal escape sequences, other
control characters and invisible Unicode in what it sends. Printed raw, they can hide or
rewrite what a person reads. `printable` writes each of them as a visible escape.
"""

from __future__ import annotations

import re

# Tag characters, zero-width characters, bidirectional controls and the soft hyphen:
# shown as nothing, or as reordered text, while a model still reads them.
INVISIBLE = re.compile(
    "[\U000e0000-\U000e007f\u200b-\u200f\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069\u00ad]"
)


def printable(text: str, *, keep_newlines: bool = True) -> str:
    """The text with control and invisible characters written as `\\u{xxxx}`."""

    return "".join(_escape(char, keep_newlines) for char in text)


def _escape(char: str, keep_newlines: bool) -> str:
    if keep_newlines and char == "\n":
        return char
    code = ord(char)
    if code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0 or INVISIBLE.match(char):
        return f"\\u{{{code:04x}}}"
    return char
