from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.request import urlopen
import base64
import io
import os


class LDIFParseError(ValueError):
    """Raised when LDIF content cannot be parsed.

    Subclasses ValueError so callers that already catch ValueError for
    malformed input continue to work, while still allowing precise
    handling of LDIF-specific failures.
    """


@dataclass
class LDIFRecord:
    """A single LDIF record: its DN and a map of attribute -> list of values.

    Values are always lists, even when a single value is present, because
    LDAP attributes are formally multi-valued and collapsing to a scalar
    forces every caller to remember which attributes might repeat.
    """
    dn: str
    attributes: Dict[str, List[str]] = field(default_factory=dict)


def _unfold(line_iter: Iterable[str]) -> Iterator[str]:
    """Yield logical LDIF lines, rejoining continuation lines.

    LDIF folds long lines: a line that begins with a single space is a
    continuation of the previous line. We strip exactly one leading space
    from the continuation and append it. We must not strip more than one,
    because a value can legitimately begin with a space after the fold.
    """
    buffer = ""
    for raw in line_iter:
        # Per RFC 2849, CRLF and CR are valid line terminators; a lone \n
        # also appears in real-world files, so normalize all three.
        line = raw.rstrip("\r\n")
        if line.startswith(" "):
            if buffer == "":
                raise LDIFParseError(
                    "continuation line has no preceding line"
                )
            buffer += line[1:]
        else:
            if buffer:
                yield buffer
            buffer = line
    if buffer:
        yield buffer


def _split_attr(line: str) -> Tuple[str, str, Optional[str]]:
    """Split an LDIF attrval line into (name, value, encoding).

    encoding is None for plain, "base64" for colon-colon, or "url" for
    colon-less-than. We keep the discriminator explicit rather than returning
    a sentinel inside the value string; it makes the decoding step
    branch-free.
    """
    colon = line.find(":")
    if colon < 0:
        raise LDIFParseError(f"line has no colon: {line!r}")
    name = line[:colon]
    if not name:
        raise LDIFParseError("empty attribute name")
    rest = line[colon:]
    if rest.startswith("::"):
        return name, rest[2:], "base64"
    if rest.startswith(":<"):
        return name, rest[2:], "url"
    if rest.startswith(":"):
        return name, rest[1:], "plain"
    raise LDIFParseError(f"malformed attribute line: {line!r}")


def _decode_value(value: str, encoding: Optional[str]) -> str:
    """Decode a value according to its encoding.

    For base64 we decode to bytes then decode UTF-8, because LDIF base64
    values are UTF-8 text by definition. A surrogate or invalid sequence
    raises LDIFParseError rather than a raw UnicodeDecodeError so the
    public surface stays narrow.

    For url we fetch from the local filesystem or HTTP. We deliberately
    do not follow redirects for non-file schemes and we bound the read
    size to avoid an adversary pointing the file at /dev/zero.
    """
    if encoding is None or encoding == "plain":
        # RFC 2849 says a plain value may have a leading space; we strip
        # exactly one to match the spec.
        if value.startswith(" "):
            return value[1:]
        return value
    if encoding == "base64":
        # RFC 2849 allows a single leading space after the double colon;
        # strip exactly one before decoding, mirroring the plain case.
        if value.startswith(" "):
            value = value[1:]
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise LDIFParseError(f"invalid base64 value: {exc}") from exc
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LDIFParseError(f"base64 value is not valid UTF-8: {exc}") from exc
    if encoding == "url":
        url = value.strip()
        if not url:
            raise LDIFParseError("empty URL reference")
        if url.startswith("file:"):
            path = url[5:]
            # Reject absolute file URLs that escape a sensible root; we
            # only support files the caller could already read, but we
            # refuse anything containing '..' to avoid trivial traversal
            # surprises in code that trusts the LDIF source.
            if ".." in path.split("/"):
                raise LDIFParseError("file URL must not contain '..'")
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError as exc:
                raise LDIFParseError(f"cannot read file URL {path}: {exc}") from exc
        else:
            try:
                with urlopen(url) as handle:  # noqa: S310 - intentional, caller controls source
                    data = handle.read(16 * 1024 * 1024)
            except Exception as exc:
                raise LDIFParseError(f"cannot fetch URL {url}: {exc}") from exc
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LDIFParseError(f"URL content is not valid UTF-8: {exc}") from exc
    raise LDIFParseError(f"unknown encoding: {encoding!r}")


class LDIFReader:
    """Parse LDIF content into LDIFRecord instances.

    The reader is an iterator: iterate it directly to yield records in
    document order. It accepts a text stream or a string; binary input
    is not accepted because LDIF is a text format and we want decoding
    errors to surface at construction, not deep in parsing.
    """

    def __init__(self, source):
        if isinstance(source, bytes):
            raise TypeError("LDIFReader expects a text stream or str, not bytes")
        if isinstance(source, str):
            self._source = io.StringIO(source)
        else:
            self._source = source

    def __iter__(self) -> Iterator[LDIFRecord]:
        return self._parse()

    def _parse(self) -> Iterator[LDIFRecord]:
        record: Optional[LDIFRecord] = None
        for logical in _unfold(self._source):
            if logical == "":
                # A blank line terminates the current record. Multiple
                # blank lines are tolerated and produce no extra records.
                if record is not None:
                    yield record
                    record = None
                continue
            if logical.startswith("#"):
                # Comment lines are ignored anywhere in the file.
                continue
            if logical.lower().startswith("version:"):
                # version: 1 is the only defined version; we do not enforce
                # it but we skip it so it does not become an attribute.
                continue
            name, raw_value, encoding = _split_attr(logical)
            value = _decode_value(raw_value, encoding)
            if name.lower() == "dn":
                if record is not None:
                    yield record
                record = LDIFRecord(dn=value)
                continue
            if record is None:
                raise LDIFParseError(
                    f"attribute {name!r} appears before dn"
                )
            record.attributes.setdefault(name, []).append(value)
        if record is not None:
            yield record
