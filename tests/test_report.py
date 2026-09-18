"""Tests for the printed report."""

import datetime
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from authlogsessions import parse  # noqa: E402
from authlogsessions import report  # noqa: E402
import log_builder as build  # noqa: E402


def report_from(lines, **kwargs):
    events = [event for event in (parse.parse_line(line, **kwargs) for line in lines)
              if event is not None]
    return report.Report(events, ["/var/log/auth.log"], len(lines), host="web01")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.lines = build.brute_force_log() + build.scanner_log() + build.quiet_log()
        self.report = report_from(self.lines)

    def test_the_addresses_are_found(self):
        self.assertEqual(len(self.report.sources), 3)

    def test_the_window_spans_the_whole_log(self):
        self.assertLess(self.report.first, self.report.last)

    def test_unrecognised_lines_are_counted(self):
        quiet = report_from(build.quiet_log() + [build.sshd(
            datetime.datetime(2026, 9, 15, 9, 0, 0), "subsystem request for sftp")])
        self.assertEqual(len(quiet.unrecognised), 1)

    def test_narrowing_to_one_address(self):
        narrowed = self.report.only("203.0.113.5")
        self.assertEqual(len(narrowed.sources), 1)
        self.assertEqual(narrowed.sources[0].address, "203.0.113.5")

    def test_narrowing_keeps_the_unrecognised_count(self):
        narrowed = self.report.only("203.0.113.5")
        self.assertEqual(len(narrowed.unrecognised), len(self.report.unrecognised))


class RenderTests(unittest.TestCase):
    def setUp(self):
        lines = build.brute_force_log() + build.scanner_log() + build.quiet_log()
        self.report = report_from(lines)
        self.text = report.render(self.report)

    def test_the_header_counts_what_it_read(self):
        self.assertIn("1 file(s)", self.text)
        self.assertIn("source address(es)", self.text)
        self.assertIn("host web01", self.text)

    def test_the_sections_are_there(self):
        self.assertIn("sources, busiest first", self.text)
        self.assertIn("what stands out", self.text)

    def test_the_attack_is_described(self):
        self.assertIn("203.0.113.5", self.text)
        self.assertIn("got in as root", self.text)
        self.assertIn("usernames:", self.text)

    def test_the_commands_after_the_login_are_shown(self):
        self.assertIn("/etc/shadow", self.text)

    def test_the_account_change_is_shown(self):
        self.assertIn("backdoor", self.text)

    def test_the_quiet_address_is_not_accused_of_anything(self):
        self.assertIn("10.0.0.4", self.text)
        findings = self.text.split("what stands out")[1]
        self.assertNotIn("10.0.0.4", findings)

    def test_a_port_less_line_joins_the_connection_it_belongs_to(self):
        # The pam failure in the attack log names an address and no port, and it
        # happened on the one connection that address had open.
        attacker = [line for line in self.text.split("\n") if line.startswith("203.0.113.5")]
        self.assertTrue(attacker)
        self.assertIn("1 connection(s)", " ".join(
            line for line in self.text.split("\n") if "203.0.113.5" in line and "connection" in line))

    def test_top_limits_the_table_and_says_what_is_left(self):
        text = report.render(self.report, top=1)
        self.assertIn("and 2 more", text)

    def test_narrowing_prints_only_that_address(self):
        text = report.render(self.report, focus="198.51.100.9")
        self.assertNotIn("203.0.113.5", text)
        self.assertIn("198.51.100.9", text)

    def test_an_address_that_is_not_there_says_so(self):
        text = report.render(self.report, focus="192.0.2.99")
        self.assertIn("nothing from 192.0.2.99", text)

    def test_an_unrecognised_line_is_reported_with_its_text(self):
        lines = build.quiet_log() + [build.sshd(
            datetime.datetime(2026, 9, 15, 9, 0, 0), "subsystem request for sftp")]
        text = report.render(report_from(lines))
        self.assertIn("not recognised", text)
        self.assertIn("subsystem request", text)

    def test_a_syslog_log_still_renders_without_a_year(self):
        text = report.render(report_from(build.quiet_log()))
        self.assertIn("window", text)


class JsonTests(unittest.TestCase):
    def test_the_reconstruction_survives_the_round_trip(self):
        lines = build.brute_force_log() + build.quiet_log()
        data = json.loads(json.dumps(report.as_dict(report_from(lines))))
        self.assertEqual(len(data["sources"]), 2)
        attacker = [item for item in data["sources"] if item["address"] == "203.0.113.5"][0]
        self.assertEqual(attacker["succeeded_as"], ["root"])
        self.assertIn("backdoor", [change["user"] for change in attacker["account_changes"]])
        self.assertTrue(data["findings"])

    def test_top_limits_the_sources(self):
        lines = build.brute_force_log() + build.scanner_log() + build.quiet_log()
        data = report.as_dict(report_from(lines), top=1)
        self.assertEqual(len(data["sources"]), 1)

    def test_the_times_are_iso_strings(self):
        data = report.as_dict(report_from(build.quiet_log()))
        self.assertIn("T", data["sources"][0]["first"])


class FormattingTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(report.human_duration(30), "30 seconds")
        self.assertEqual(report.human_duration(600), "10 minutes")
        self.assertEqual(report.human_duration(7200), "2.0 hours")
        self.assertEqual(report.human_duration(None), "unknown")

    def test_a_stamp(self):
        self.assertEqual(report.stamp(datetime.datetime(2026, 9, 15, 3, 12, 44)),
                         "2026-09-15 03:12:44")
        self.assertEqual(report.stamp(None), "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
