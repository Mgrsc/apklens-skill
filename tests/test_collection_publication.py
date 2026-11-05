import errno
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.static_analysis import common
from scripts.static_analysis.common import (
    AnalysisError,
    Cancelled,
    Limits,
    publish_collected_file,
)


class CollectionPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "pull.apk"
        self.data = b"private collected artifact" * 1000
        self.source.write_bytes(self.data)
        self.directory = self.root / "artifacts"
        self.cancel = threading.Event()
        self.limits = Limits()
        self.identity = hashlib.sha256(self.data).hexdigest()

    def publish(self):
        return publish_collected_file(
            self.source, self.directory, self.limits, self.cancel
        )

    def test_private_pull_is_hardlinked_without_copying(self):
        with patch.object(
            common, "snapshot_file", side_effect=AssertionError("Unexpected copy")
        ):
            result = self.publish()
        destination = Path(result["path"])
        self.assertEqual(result["sha256"], self.identity)
        self.assertEqual(destination.stat().st_ino, self.source.stat().st_ino)
        self.source.unlink()
        self.assertEqual(destination.read_bytes(), self.data)

    def test_existing_content_is_validated_and_never_replaced(self):
        result = self.publish()
        destination = Path(result["path"])
        inode = destination.stat().st_ino
        self.assertEqual(self.publish(), result)
        self.assertEqual(destination.stat().st_ino, inode)
        self.source.unlink()
        self.source.write_bytes(self.data)
        destination.write_bytes(b"corrupt")
        with self.assertRaisesRegex(AnalysisError, "failed validation"):
            self.publish()
        self.assertEqual(destination.read_bytes(), b"corrupt")
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_symlink_inputs_and_destinations_are_rejected(self):
        actual = self.root / "actual.apk"
        self.source.rename(actual)
        self.source.symlink_to(actual)
        with self.assertRaises(AnalysisError):
            self.publish()
        self.source.unlink()
        actual.rename(self.source)
        self.directory.mkdir(exist_ok=True)
        destination = self.directory / f"{self.identity}.apk"
        destination.symlink_to(self.source)
        with self.assertRaises(AnalysisError):
            self.publish()
        self.assertTrue(destination.is_symlink())

    def test_cross_filesystem_uses_copy_and_keeps_private_source(self):
        link = os.link

        def across(source, destination, **kwargs):
            if Path(source) == self.source:
                raise OSError(errno.EXDEV, "Synthetic cross-device link")
            return link(source, destination, **kwargs)

        with patch.object(common.os, "link", side_effect=across):
            result = self.publish()
        destination = Path(result["path"])
        self.assertEqual(destination.read_bytes(), self.data)
        self.assertNotEqual(destination.stat().st_ino, self.source.stat().st_ino)
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_filesystem_without_hardlinks_keeps_unique_completed_copy(self):
        with patch.object(
            common.os,
            "link",
            side_effect=OSError(errno.EOPNOTSUPP, "Synthetic unsupported link"),
        ):
            result = self.publish()
        self.assertEqual(Path(result["path"]).parent, self.directory)
        self.assertEqual(Path(result["path"]).read_bytes(), self.data)
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_cancelled_or_changed_pull_is_not_published(self):
        self.cancel.set()
        with self.assertRaises(Cancelled):
            self.publish()
        self.cancel.clear()
        original = common.hash_regular_file

        def changed(*arguments):
            result = original(*arguments)
            self.source.write_bytes(b"changed")
            return result

        with (
            patch.object(common, "hash_regular_file", side_effect=changed),
            self.assertRaisesRegex(AnalysisError, "changed before publication"),
        ):
            self.publish()
        self.assertEqual(list(self.directory.iterdir()), [])
