# ldif_reader

A small, dependency-free Python parser for LDIF (LDAP Data Interchange Format) that yields records with their DN and attributes, handling folded lines, base64 values, and URL references.

```python
from ldif_reader import LDIFReader, LDIFRecord, LDIFParseError

ldif = """
dn: uid=jane,ou=people
uid: jane
cn:: SmFuZSBEb2U=
"""

for record in LDIFReader(ldif):  # record: LDIFRecord
    print(record.dn, record.attributes)
```

`LDIFReader` accepts a text stream or a `str`; pass `bytes` and it raises `TypeError`. Each yielded `LDIFRecord` has a `dn: str` and `attributes: Dict[str, List[str]]`. `LDIFParseError` is raised on malformed input (a `ValueError` subclass, so existing `except ValueError` handlers still catch it).

## Why this exists

LDIF is a text format for bulk LDAP import and export. Tools that emit it fold long lines at column 80, encode non-ASCII DNs as base64, and sometimes point at external content via `:<` URL references. Parsing all three correctly by hand is fiddly, and the standard library has no LDIF module. This library exists to fill that gap with no dependencies.

The trade-off: this is a reader, not a writer. It does not validate attribute names against a schema, it does not resolve LDAP DNs against a directory, and URL references are fetched eagerly with a 16 MiB cap to keep a hostile or buggy LDIF file from consuming unbounded memory.

## The awkward edge

A continuation line in LDIF begins with exactly one space. That space is the fold marker and is stripped; any further leading spaces are part of the value. `ldif_reader` preserves those additional spaces rather than collapsing runs of whitespace, so values round-trip faithfully.

If a base64 value does not decode to valid UTF-8 (the LDIF spec mandates UTF-8), parsing fails with `LDIFParseError` rather than silently substituting a replacement character.
