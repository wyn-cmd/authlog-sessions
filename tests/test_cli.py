"""Tests for the command line, driven through main()."""

import gzip
import io
import json
import os
import sys
import tempfile
import unittest

from contextlib import redirect_stdout, redirect_stderr

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from authlogsessions import cli  # noqa: E402
import log_builder as build  # noqa: E402


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="authlog-cli-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))

        self.attack = os.path.join(self.work, "auth.log")
        with open(self.attack, "w", encoding="utf-8") as handle:
            handle.write("".join(build.brute_force_log()))

        self.mixed = os.path.join(self.work, "auth.log.1")
        with open(self.mixed, "w", encoding="utf-8") as handle:
            handle.write("".join(build.brute_force_log() + build.scanner_log()
                                 + build.quiet_log()))

        self.rotated = os.path.join(self.work, "auth.log.2.gz")
        with gzip.open(self.rotated, "wt", encoding="utf-8") as handle:
            handle.write("".join(build.scanner_log()))

    def test_a_report_is_printed(self):
        code, out, _ = run([self.attack])
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.5", out)
        self.assertIn("got in as root", out)
        self.assertIn("what stands out", out)

    def test_several_files_at_once(self):
        code, out, _ = run([self.mixed, self.rotated])
        self.assertEqual(code, 0)
        self.assertIn("2 file(s)", out)

    def test_a_gzipped_rotated_log_is_read(self):
        code, out, _ = run([self.rotated])
        self.assertEqual(code, 0)
        self.assertIn("198.51.100.9", out)

    def test_narrowing_to_one_source(self):
        code, out, _ = run([self.mixed, "--source", "198.51.100.9"])
        self.assertEqual(code, 0)
        self.assertIn("198.51.100.9", out)
        self.assertNotIn("203.0.113.5", out)

    def test_json_comes_out_parseable(self):
        code, out, _ = run([self.mixed, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data["sources"]), 3)
        self.assertTrue(data["findings"])

    def test_top_limits_the_report(self):
        code, out, _ = run([self.mixed, "--top", "1"])
        self.assertEqual(code, 0)
        self.assertIn("and 2 more", out)

    def test_a_time_window_narrows_the_report(self):
        code, out, _ = run([self.mixed, "--since", "2026-09-15T03:24:00"])
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.5", out)

    def test_a_window_with_nothing_in_it_is_reported(self):
        code, _, err = run([self.attack, "--since", "2030-01-01"])
        self.assertEqual(code, 1)
        self.assertIn("inside that window", err)

    def test_a_time_that_makes_no_sense_is_refused(self):
        code, _, err = run([self.attack, "--since", "whenever"])
        self.assertEqual(code, 2)
        self.assertIn("as a time", err)

    def test_a_year_can_be_given_for_syslog(self):
        code, out, _ = run([self.attack, "--year", "2024"])
        self.assertEqual(code, 0)
        self.assertIn("2024-09-15", out)

    def test_min_attempts_hides_the_quiet_scanners(self):
        code, out, _ = run([self.mixed, "--min-attempts", "20"])
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.5", out)
        self.assertNotIn("10.0.0.4", out)

    def test_quiet_leaves_out_the_narratives(self):
        code, out, _ = run([self.attack, "--quiet"])
        self.assertEqual(code, 0)
        self.assertIn("sources, busiest first", out)
        self.assertNotIn("usernames:", out)

    def test_a_missing_file_is_reported(self):
        code, _, err = run([os.path.join(self.work, "absent.log")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_a_directory_is_reported(self):
        code, _, err = run([self.work])
        self.assertEqual(code, 2)
        self.assertIn("directory", err)

    def test_a_file_with_no_log_lines_is_reported(self):
        junk = os.path.join(self.work, "notes.txt")
        with open(junk, "w", encoding="utf-8") as handle:
            handle.write("this file is not a log at all\n" * 5)
        code, _, err = run([junk])
        self.assertEqual(code, 1)
        self.assertIn("looked like a log line", err)

    def test_top_of_zero_is_refused(self):
        code, _, err = run([self.attack, "--top", "0"])
        self.assertEqual(code, 2)
        self.assertIn("at least 1", err)

    def test_version_exits_cleanly(self):
        with self.assertRaises(SystemExit) as caught:
            run([self.attack, "--version"])
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
