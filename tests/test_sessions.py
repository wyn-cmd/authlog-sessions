"""Tests for the reconstruction itself."""

import datetime
import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from authlogsessions import parse  # noqa: E402
from authlogsessions import sessions  # noqa: E402
import log_builder as build  # noqa: E402

WHEN = datetime.datetime(2026, 9, 15, 3, 12, 44)


def events_from(lines, **kwargs):
    return [event for event in (parse.parse_line(line, **kwargs) for line in lines)
            if event is not None]


def reconstruct_from(lines):
    return sessions.reconstruct(events_from(lines))


class ConnectionTests(unittest.TestCase):
    def test_one_port_is_one_connection(self):
        lines = [build.failed(WHEN, "root", "203.0.113.5", 51234),
                 build.failed(WHEN + datetime.timedelta(seconds=5), "admin", "203.0.113.5", 51234)]
        connections = sessions.build_connections(events_from(lines))
        self.assertEqual(len(connections), 1)
        self.assertEqual(len(connections[0].events), 2)

    def test_a_second_port_is_a_second_connection(self):
        lines = [build.failed(WHEN, "root", "203.0.113.5", 51234),
                 build.failed(WHEN, "root", "203.0.113.5", 51235)]
        connections = sessions.build_connections(events_from(lines))
        self.assertEqual(len(connections), 2)

    def test_events_without_an_address_are_left_out_of_connections(self):
        lines = [build.sshd(WHEN, "pam_unix(sshd:session): session opened for user root")]
        self.assertEqual(sessions.build_connections(events_from(lines)), [])

    def test_connections_come_back_earliest_first(self):
        lines = [build.failed(WHEN + datetime.timedelta(minutes=5), "root", "203.0.113.5", 9),
                 build.failed(WHEN, "root", "203.0.113.5", 10)]
        connections = sessions.build_connections(events_from(lines))
        self.assertEqual([connection.port for connection in connections], [10, 9])

    def test_the_window_of_a_connection_is_its_first_and_last_event(self):
        lines = [build.failed(WHEN, "root", "203.0.113.5", 51234),
                 build.accepted(WHEN + datetime.timedelta(minutes=2), "root", "203.0.113.5", 51234)]
        connection = sessions.build_connections(events_from(lines))[0]
        self.assertEqual(connection.first, WHEN)
        self.assertEqual(connection.last, WHEN + datetime.timedelta(minutes=2))


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.sources, self.orphans = reconstruct_from(build.brute_force_log())
        self.attack = self.sources[0]

    def test_one_source_for_one_address(self):
        self.assertEqual(len(self.sources), 1)
        self.assertEqual(self.attack.address, "203.0.113.5")

    def test_failures_and_successes_are_counted(self):
        self.assertEqual(self.attack.successes, 1)
        self.assertEqual(self.attack.failures, 25)

    def test_the_usernames_it_tried_are_kept(self):
        self.assertIn("admin", self.attack.usernames)
        self.assertEqual(len(self.attack.usernames), 18)

    def test_sources_come_back_busiest_first(self):
        sources, _ = reconstruct_from(build.scanner_log() + build.brute_force_log())
        self.assertEqual(sources[0].address, "203.0.113.5")


class AttributionTests(unittest.TestCase):
    """sudo leaves no address on the line, so it has to be placed by account."""

    def setUp(self):
        self.sources, self.orphans = reconstruct_from(build.brute_force_log())
        self.attack = self.sources[0]

    def test_commands_after_a_login_land_on_the_address_that_logged_in(self):
        self.assertEqual(len(self.attack.commands), 3)
        self.assertIn("/etc/shadow", self.attack.commands[0].detail)

    def test_the_account_it_created_lands_on_the_same_address(self):
        self.assertEqual(len(self.attack.accounts), 1)
        self.assertEqual(self.attack.accounts[0].user, "backdoor")

    def test_a_command_with_no_matching_login_is_left_as_an_orphan(self):
        lines = [build.sudo(WHEN, "someone", "/bin/ls")]
        sources, orphans = reconstruct_from(lines)
        self.assertEqual(sources, [])
        self.assertEqual(len(orphans), 1)

    def test_a_command_before_any_login_is_left_alone(self):
        # Nothing was logged in at the time, so there is no honest place to put
        # this. It comes back as an orphan rather than being handed to whoever
        # logged in later.
        lines = [build.sudo(WHEN, "root", "/bin/cat /etc/shadow"),
                 build.accepted(WHEN + datetime.timedelta(minutes=1), "root",
                                "203.0.113.5", 51234)]
        sources, orphans = reconstruct_from(lines)
        self.assertEqual(sources[0].commands, [])
        self.assertEqual(len(orphans), 1)

    def test_an_account_change_is_tied_to_the_session_that_was_open(self):
        lines = [build.accepted(WHEN, "root", "203.0.113.5", 51234),
                 build.user_added(WHEN + datetime.timedelta(minutes=1), "backdoor")]
        sources, orphans = reconstruct_from(lines)
        self.assertEqual(len(sources[0].accounts), 1)
        self.assertEqual(sources[0].accounts[0].user, "backdoor")
        self.assertEqual(orphans, [])


class OutcomeTests(unittest.TestCase):
    def test_an_address_that_never_got_in(self):
        sources, _ = reconstruct_from(build.scanner_log())
        self.assertEqual(sessions.outcome(sources[0]), "no successful login")
        self.assertEqual(sessions.succeeded_as(sources[0]), [])

    def test_an_address_that_needed_failures_first(self):
        sources, _ = reconstruct_from(build.brute_force_log())
        self.assertIn("after 25 failure", sessions.outcome(sources[0]))

    def test_an_address_that_got_in_first_try(self):
        sources, _ = reconstruct_from(build.quiet_log())
        self.assertIn("without a single failure", sessions.outcome(sources[0]))

    def test_the_rate_is_attempts_per_minute(self):
        sources, _ = reconstruct_from(build.scanner_log())
        self.assertGreater(sessions.rate(sources[0]), 10)

    def test_a_window_of_zero_minutes_is_treated_as_one(self):
        sources, _ = reconstruct_from(build.quiet_log())
        self.assertGreaterEqual(sessions.minutes(sources[0]), 1.0)


class FindingTests(unittest.TestCase):
    def findings_for(self, lines):
        sources, _ = reconstruct_from(lines)
        return " | ".join(sessions.findings(sources))

    def test_a_login_after_many_failures_is_named(self):
        self.assertIn("failed 25 time(s) and then got in",
                      self.findings_for(build.brute_force_log()))

    def test_an_account_created_after_logging_in_is_named(self):
        self.assertIn("changed accounts after logging in",
                      self.findings_for(build.brute_force_log()))

    def test_commands_after_a_login_are_named(self):
        self.assertIn("command(s) recorded after authenticating",
                      self.findings_for(build.brute_force_log()))

    def test_a_password_login_with_no_failures_first_is_named(self):
        lines = [build.accepted(WHEN, "root", "203.0.113.5", 51234)]
        self.assertIn("with no failed attempt before it", self.findings_for(lines))

    def test_a_key_login_is_not_treated_as_suspicious(self):
        # Keys are meant to work first time, so a deploy account logging in with
        # one is not news and should not be printed as though it were.
        self.assertNotIn("with no failed attempt before it",
                         self.findings_for(build.quiet_log()))

    def test_a_fast_scanner_is_named(self):
        self.assertIn("attempts a minute", self.findings_for(build.scanner_log()))

    def test_a_dictionary_is_named_when_it_did_not_work(self):
        lines = []
        names = ["admin", "root", "test", "oracle", "postgres", "ubuntu", "pi",
                 "user", "ftpuser", "jenkins", "git", "deploy"]
        for index, name in enumerate(names):
            lines.append(build.failed(WHEN + datetime.timedelta(seconds=index),
                                      name, "203.0.113.5", 51234, invalid=True))
        self.assertIn("different usernames", self.findings_for(lines))

    def test_an_ordinary_log_has_nothing_to_say(self):
        sources, _ = reconstruct_from(build.quiet_log())
        # Ordinary key logins are not findings.
        self.assertEqual(sessions.findings(sources), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
