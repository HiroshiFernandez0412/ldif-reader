from __future__ import annotations

import io
import os
import tempfile
import unittest

from ldif_reader import LDIFReader, LDIFRecord, LDIFParseError


class TestUnfolding(unittest.TestCase):
    def test_folded_line_is_rejoined(self):
        text = "dn: cn=one,\n ou=people\n"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].dn, "cn=one,ou=people")

    def test_multiple_folds(self):
        text = "dn: a,\n b,\n c\n"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].dn, "a,b,c")

    def test_continuation_preserves_leading_space(self):
        # The single leading space of the continuation is the fold marker
        # and is removed; any further spaces belong to the value.
        text = "dn: a\ndescription: a\n  b\n"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].attributes["description"], ["a b"])

    def test_lone_continuation_raises(self):
        with self.assertRaises(LDIFParseError):
            list(LDIFReader(" continued\n"))


class TestPlainValues(unittest.TestCase):
    def test_simple_record(self):
        text = "dn: uid=jane,ou=people\nuid: jane\ncn: Jane Doe\n"
        records = list(LDIFReader(text))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].dn, "uid=jane,ou=people")
        self.assertEqual(records[0].attributes["uid"], ["jane"])
        self.assertEqual(records[0].attributes["cn"], ["Jane Doe"])

    def test_multi_valued_attribute(self):
        text = (
            "dn: uid=jane,ou=people\n"
            "mail: jane@example.org\n"
            "mail: jane@other.example\n"
        )
        records = list(LDIFReader(text))
        self.assertEqual(
            records[0].attributes["mail"],
            ["jane@example.org", "jane@other.example"],
        )

    def test_dn_case_insensitive(self):
        records = list(LDIFReader("DN: uid=jane\n"))
        self.assertEqual(records[0].dn, "uid=jane")

    def test_attribute_before_dn_raises(self):
        with self.assertRaises(LDIFParseError):
            list(LDIFReader("uid: jane\n"))

    def test_blank_line_separates_records(self):
        text = "dn: a\n\ndn: b\n"
        records = list(LDIFReader(text))
        self.assertEqual([r.dn for r in records], ["a", "b"])

    def test_multiple_blank_lines_collapse(self):
        text = "dn: a\n\n\n\ndn: b\n"
        records = list(LDIFReader(text))
        self.assertEqual([r.dn for r in records], ["a", "b"])

    def test_trailing_record_without_blank_is_emitted(self):
        text = "dn: a\nuid: x\n"
        records = list(LDIFReader(text))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].attributes["uid"], ["x"])

    def test_comment_lines_ignored(self):
        text = "# a comment\ndn: a\n# another\nuid: x\n"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].attributes["uid"], ["x"])

    def test_version_line_skipped(self):
        text = "version: 1\n\ndn: a\nuid: x\n"
        records = list(LDIFReader(text))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].dn, "a")


class TestBase64(unittest.TestCase):
    def test_base64_value(self):
        # "Jane Doe" in base64
        text = "dn: uid=jane\ncn:: SmFuZSBEb2U=\n"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].attributes["cn"], ["Jane Doe"])

    def test_base64_dn(self):
        text = "dn:: dWlkPWphbmU=\n"  # "uid=jane"
        records = list(LDIFReader(text))
        self.assertEqual(records[0].dn, "uid=jane")

    def test_invalid_base64_raises(self):
        text = "dn: a\ncn:: not!base64\n"
        with self.assertRaises(LDIFParseError):
            list(LDIFReader(text))


class TestUrl(unittest.TestCase):
    def test_file_url(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ldif", delete=False) as f:
            f.write("hello from file")
            path = f.name
        try:
            url = "file:" + path
            text = f"dn: a\ndescription:< {url}\n"
            records = list(LDIFReader(text))
            self.assertEqual(records[0].attributes["description"], ["hello from file"])
        finally:
            os.unlink(path)

    def test_file_url_traversal_rejected(self):
        text = "dn: a\ndescription:< file:../etc/passwd\n"
        with self.assertRaises(LDIFParseError):
            list(LDIFReader(text))

    def test_missing_file_raises(self):
        text = "dn: a\ndescription:< file:/no/such/file/here\n"
        with self.assertRaises(LDIFParseError):
            list(LDIFReader(text))


class TestStream(unittest.TestCase):
    def test_accepts_text_stream(self):
        stream = io.StringIO("dn: a\nuid: x\n")
        records = list(LDIFReader(stream))
        self.assertEqual(records[0].dn, "a")

    def test_rejects_bytes(self):
        with self.assertRaises(TypeError):
            LDIFReader(b"dn: a\n")


class TestRecordType(unittest.TestCase):
    def test_record_is_ldifrecord(self):
        records = list(LDIFReader("dn: a\n"))
        self.assertIsInstance(records[0], LDIFRecord)

    def test_attributes_default_empty(self):
        record = LDIFRecord(dn="x")
        self.assertEqual(record.attributes, {})


if __name__ == "__main__":
    unittest.main()
