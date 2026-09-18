"""Tests for reading log lines."""

import datetime
import gzip
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from authlogsessions import parse  # noqa: E402
import log_builder as build  # noqa: E402

WHEN = datetime.datetime(2026, 9, 15, 3, 12, 44)


class TimestampTests(unittest.TestCase):
    def test_a_syslog_stamp_needs_the_year_from_somewhere(self):
        stamp = parse.parse_stamp("Sep 15 03:12:44 web01 sshd[1]: hello", year=2024)
        self.assertEqual(stamp, datetime.datetime(2024, 9, 15, 3, 12, 44))

    def test_the_year_falls_back_when_it_is_not_given(self):
        stamp = parse.parse_stamp("Sep 15 03:12:44 web01 sshd[1]: hello",
                                 fallback_year=2019)
        self.assertEqual(stamp.year, 2019)

    def test_an_iso_stamp_carries_its_own_year(self):
        stamp = parse.parse_stamp("2026-09-15T03:12:44.123456+08:00 web01 sshd[1]: x")
        self.assertEqual(stamp.year, 2026)
        self.assertEqual(stamp.hour, 3)

    def test_a_zulu_stamp_is_read(self):
        stamp = parse.parse_stamp("2026-09-15T03:12:44Z web01 sshd[1]: x")
        self.assertEqual(stamp.tzinfo is not None, True)

    def test_a_line_with_no_stamp_has_none(self):
        self.assertIsNone(parse.parse_stamp("sshd[1]: Failed password"))

    def test_the_stamp_comes_off_the_front(self):
        body = parse.strip_stamp("Sep 15 03:12:44 web01 sshd[1]: Failed password")
        self.assertEqual(body, "web01 sshd[1]: Failed password")


class FieldTests(unittest.TestCase):
    def test_an_ipv4_address(self):
        self.assertEqual(parse.find_address("from 203.0.113.5 port 22"),
                         "203.0.113.5")

    def test_an_ipv6_address(self):
        self.assertEqual(parse.find_address("from 2001:db8::1 port 22"),
                         "2001:db8::1")

    def test_no_address(self):
        self.assertIsNone(parse.find_address("session opened for user root"))

    def test_a_port(self):
        self.assertEqual(parse.find_port("from 10.0.0.1 port 51234 ssh2"), 51234)

    def test_a_username_after_for(self):
        self.assertEqual(parse.find_user("Failed password for root from x"), "root")

    def test_a_username_in_a_pair(self):
        self.assertEqual(parse.find_user("rhost=10.0.0.1  user=deploy"), "deploy")


class LineTests(unittest.TestCase):
    def parse_one(self, line, **kwargs):
        return parse.parse_line(line, **kwargs)

    def test_a_failed_password(self):
        event = self.parse_one(build.failed(WHEN, "root", "203.0.113.5", 51234))
        self.assertEqual(event.action, parse.FAILED_PASSWORD)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.address, "203.0.113.5")
        self.assertEqual(event.port, 51234)
        self.assertEqual(event.source, "sshd")
        self.assertEqual(event.host, "web01")

    def test_a_failed_password_for_an_invalid_user(self):
        event = self.parse_one(build.failed(WHEN, "admin", "203.0.113.5", 51234, invalid=True))
        self.assertEqual(event.action, parse.FAILED_PASSWORD)
        self.assertEqual(event.user, "admin")

    def test_an_invalid_user_line(self):
        event = self.parse_one(build.sshd(WHEN, "Invalid user test from 203.0.113.5"))
        self.assertEqual(event.action, parse.INVALID_USER)
        self.assertEqual(event.user, "test")

    def test_accepted_password(self):
        event = self.parse_one(build.accepted(WHEN, "root", "203.0.113.5", 51234))
        self.assertEqual(event.action, parse.ACCEPTED_PASSWORD)
        self.assertEqual(event.user, "root")

    def test_accepted_publickey(self):
        event = self.parse_one(build.accepted(WHEN, "deploy", "10.0.0.4", 55000, key=True))
        self.assertEqual(event.action, parse.ACCEPTED_KEY)

    def test_a_session_opening_and_closing(self):
        opened = self.parse_one(build.sshd(WHEN, "pam_unix(sshd:session): "
                                                "session opened for user root by (uid=0)"))
        closed = self.parse_one(build.sshd(WHEN, "pam_unix(sshd:session): "
                                                "session closed for user root"))
        self.assertEqual(opened.action, parse.SESSION_OPENED)
        self.assertEqual(opened.user, "root")
        self.assertEqual(closed.action, parse.SESSION_CLOSED)

    def test_a_disconnect(self):
        event = self.parse_one(build.sshd(WHEN, "Received disconnect from 203.0.113.5 "
                                               "port 51234:11: Bye Bye [preauth]"))
        self.assertEqual(event.action, parse.DISCONNECTED)
        self.assertEqual(event.address, "203.0.113.5")

    def test_a_connection_closing_before_login(self):
        event = self.parse_one(build.sshd(WHEN, "Connection closed by 198.51.100.9 "
                                               "port 40001 [preauth]"))
        self.assertEqual(event.action, parse.CLOSED)

    def test_a_reset_connection(self):
        event = self.parse_one(build.sshd(
            WHEN, "Connection reset by 203.0.113.5 port 51234 [preauth]"))
        self.assertEqual(event.action, parse.CLOSED)
        self.assertEqual(event.address, "203.0.113.5")

    def test_a_connection_that_timed_out(self):
        event = self.parse_one(build.sshd(
            WHEN, "Timeout before authentication for 203.0.113.5 port 51234"))
        self.assertEqual(event.action, parse.CLOSED)

    def test_giving_up_after_too_many_attempts(self):
        event = self.parse_one(build.sshd(
            WHEN, "error: maximum authentication attempts exceeded for root from "
                  "203.0.113.5 port 51234 ssh2 [preauth]"))
        self.assertEqual(event.action, parse.MAX_ATTEMPTS)
        self.assertEqual(event.user, "root")

    def test_a_pam_failure(self):
        event = self.parse_one(build.pam_failure(WHEN, "root", "203.0.113.5"))
        self.assertEqual(event.action, parse.PAM_FAILURE)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.address, "203.0.113.5")

    def test_a_sudo_command_keeps_the_command_line(self):
        event = self.parse_one(build.sudo(WHEN, "root", "/bin/cat /etc/shadow"))
        self.assertEqual(event.action, parse.SUDO_COMMAND)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.detail, "/bin/cat /etc/shadow")

    def test_a_new_account(self):
        event = self.parse_one(build.user_added(WHEN, "backdoor"))
        self.assertEqual(event.action, parse.ACCOUNT_CHANGE)
        self.assertEqual(event.user, "backdoor")
        self.assertEqual(event.detail, "user added")

    def test_something_unrecognised_is_kept_rather_than_dropped(self):
        event = self.parse_one(build.sshd(WHEN, "subsystem request for sftp by user root"))
        self.assertEqual(event.action, parse.UNKNOWN)

    def test_a_session_line_from_openssh_eight(self):
        event = self.parse_one(build.sshd(
            WHEN, "Starting session 42 of user root from 203.0.113.5 port 51234"))
        self.assertEqual(event.action, parse.SESSION_OPENED)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.address, "203.0.113.5")

    def test_a_close_session_line_from_openssh_eight(self):
        event = self.parse_one(build.sshd(
            WHEN, "Close session: user root from 203.0.113.5 port 51234"))
        self.assertEqual(event.action, parse.SESSION_CLOSED)

    def test_a_line_with_no_process_tag_is_not_a_log_line(self):
        self.assertIsNone(self.parse_one("just some text with no tag"))

    def test_a_blank_line_is_not_a_log_line(self):
        self.assertIsNone(self.parse_one("\n"))


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="authlog-read-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))

    def test_a_plain_file(self):
        path = os.path.join(self.work, "auth.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("".join(build.brute_force_log()))
        rows = list(parse.read_lines([path]))
        self.assertEqual(len(rows), len(build.brute_force_log()))
        self.assertEqual(rows[0][1], 1)

    def test_a_gzipped_rotated_log(self):
        path = os.path.join(self.work, "auth.log.1.gz")
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write("".join(build.scanner_log()))
        rows = list(parse.read_lines([path]))
        self.assertEqual(len(rows), len(build.scanner_log()))

    def test_several_files_come_back_in_order(self):
        first = os.path.join(self.work, "one.log")
        second = os.path.join(self.work, "two.log")
        for path in (first, second):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("".join(build.quiet_log()))
        rows = list(parse.read_lines([first, second]))
        self.assertEqual([row[0] for row in rows][0], first)
        self.assertEqual([row[0] for row in rows][-1], second)

    def test_a_missing_file_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            list(parse.read_lines([os.path.join(self.work, "absent.log")]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
