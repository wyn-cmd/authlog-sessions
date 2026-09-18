"""Build log lines for the tests.

No real log is committed here and none should be. An auth.log carries usernames,
source addresses and sometimes hostnames of real machines, so a fixture built
from one would be a privacy problem in a public repository. Every line the tests
use is written out here instead, in the shapes sshd and sudo actually produce.
"""

import datetime

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

HOST = "web01"


def syslog_stamp(moment):
    """The timestamp sshd writes, which carries no year."""
    return f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S}"


def iso_stamp(moment):
    """The timestamp journalctl -o short-iso writes."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S%z")


def sshd(moment, message, host=HOST, pid=1234):
    return f"{syslog_stamp(moment)} {host} sshd[{pid}]: {message}\n"


def journal(moment, message, unit="sshd", host=HOST, pid=1234):
    return f"{iso_stamp(moment)} {host} {unit}[{pid}]: {message}\n"


def failed(moment, user, address, port, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return sshd(moment, f"Failed password for {who} from {address} port {port} ssh2")


def accepted(moment, user, address, port, key=False):
    how = "publickey" if key else "password"
    return sshd(moment, f"Accepted {how} for {user} from {address} port {port} ssh2")


def pam_failure(moment, user, address):
    return sshd(moment, "pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                        f"euid=0 tty=ssh ruser= rhost={address}  user={user}")


def sudo(moment, user, command, host=HOST):
    return (f"{syslog_stamp(moment)} {host} sudo:   {user} : TTY=pts/0 ; "
            f"PWD=/home/{user} ; USER=root ; COMMAND={command}\n")


def user_added(moment, user, host=HOST):
    return (f"{syslog_stamp(moment)} {host} useradd[2001]: new user: name={user}, "
            f"UID=1001, GID=1001, home=/home/{user}, shell=/bin/bash\n")


def brute_force_log(start=None):
    """One address hammering a machine, getting in, and covering its tracks.

    The shape is the one worth catching: many failed names, one accepted login
    on the same connection, commands afterwards, and a new account at the end.
    """
    start = start or datetime.datetime(2026, 9, 15, 3, 12, 44)
    lines = []
    moment = start

    names = ["admin", "root", "test", "oracle", "postgres", "ubuntu", "pi",
             "user", "ftpuser", "jenkins", "git", "deploy", "vagrant", "mysql",
             "backup", "www", "nobody", "guest"]

    for index, name in enumerate(names):
        moment = start + datetime.timedelta(seconds=index * 30)
        lines.append(failed(moment, name, "203.0.113.5", 51234, invalid=name != "root"))

    for index in range(6):
        moment = start + datetime.timedelta(minutes=10, seconds=index * 45)
        lines.append(failed(moment, "root", "203.0.113.5", 51234))

    moment = start + datetime.timedelta(minutes=11)
    lines.append(pam_failure(moment, "root", "203.0.113.5"))

    moment = start + datetime.timedelta(minutes=11, seconds=5)
    lines.append(accepted(moment, "root", "203.0.113.5", 51234))

    moment = start + datetime.timedelta(minutes=11, seconds=6)
    lines.append(sshd(moment, "pam_unix(sshd:session): session opened for user root by (uid=0)"))

    for index, command in enumerate(("/bin/cat /etc/shadow", "/usr/sbin/useradd -m backdoor",
                                     "/usr/bin/passwd backdoor")):
        lines.append(sudo(start + datetime.timedelta(minutes=12, seconds=index * 20),
                          "root", command))

    lines.append(user_added(start + datetime.timedelta(minutes=13), "backdoor"))
    lines.append(sshd(start + datetime.timedelta(minutes=14),
                      "Received disconnect from 203.0.113.5 port 51234:11: Bye Bye"))
    return lines


def scanner_log(start=None):
    """A different address trying one name once on each of many ports."""
    start = start or datetime.datetime(2026, 9, 15, 5, 0, 0)
    lines = []
    for index in range(8):
        moment = start + datetime.timedelta(seconds=index * 5)
        lines.append(failed(moment, "root", "198.51.100.9", 40000 + index))
        lines.append(sshd(moment, f"Connection closed by 198.51.100.9 port {40000 + index} [preauth]"))
    return lines


def quiet_log(start=None):
    """Ordinary use: a couple of key logins and nothing else."""
    start = start or datetime.datetime(2026, 9, 14, 9, 0, 0)
    return [
        accepted(start, "deploy", "10.0.0.4", 55000, key=True),
        sshd(start + datetime.timedelta(seconds=2),
             "pam_unix(sshd:session): session opened for user deploy by (uid=0)"),
        sshd(start + datetime.timedelta(minutes=30),
             "pam_unix(sshd:session): session closed for user deploy"),
        accepted(start + datetime.timedelta(hours=6), "deploy", "10.0.0.4", 55010, key=True),
    ]
