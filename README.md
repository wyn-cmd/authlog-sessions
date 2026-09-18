# authlog-sessions

Rebuild what happened on a machine from its authentication logs: which addresses tried what, which attempt actually worked, what ran afterwards, and whether an account was created.

This is for the moment after you have been handed an `auth.log`, or pulled one off a box, and you want the story rather than 40,000 lines. It reads the file, reconstructs each connection, groups everything by source address, and prints a page. Nothing here talks to a machine, opens a socket or ships a log anywhere.

## What it needs

Python 3.8 or newer. Nothing else, no dependencies to install.

## Running it

```
python3 -m authlogsessions /var/log/auth.log
python3 -m authlogsessions auth.log auth.log.1 auth.log.2.gz
python3 -m authlogsessions auth.log --source 203.0.113.5
```

Rotated and compressed logs are fine. Every file is opened by its magic bytes rather than its extension, so `auth.log.1.gz` is read without being unpacked first.

To try it without a log of your own:

```
python3 examples/make-sample-log.py /tmp/auth.log
python3 -m authlogsessions /tmp/auth.log
```

The sample is assembled line by line from the builder the tests use, in the shapes sshd, sudo and useradd actually write. No real log is in this repository and none should be. An `auth.log` carries usernames, addresses and hostnames of a real machine, so a fixture copied from one would be a privacy problem the moment it was committed.

## What the output looks like

Real output from the sample above, not an illustration:

```
1 file(s), 52 line(s), 52 recognised, 3 source address(es)
host web01
window 2026-09-14 09:00:00 to 2026-09-15 05:00:35 (20.0 hours)

sources, busiest first
      28 event(s)  203.0.113.5                               1 connection(s)  got in as root after 25 failure(s)
      16 event(s)  198.51.100.9                              8 connection(s)  no successful login
       4 event(s)  10.0.0.4                                  2 connection(s)  got in as deploy without a single failure first

203.0.113.5
  active from 2026-09-15 03:12:44 to 2026-09-15 03:26:44 (14 minutes)
  1 connection(s), 28 line(s), 25 failure(s), 1 success(es)
  usernames: root x9, admin x1, test x1, oracle x1, postgres x1, and 13 more
  got in as root at 2026-09-15 03:23:49 on port 51234
  ran: /bin/cat /etc/shadow
  ran: /usr/sbin/useradd -m backdoor
  ran: /usr/bin/passwd backdoor
  account user added: backdoor

what stands out
  - 203.0.113.5 changed accounts after logging in (backdoor), which is worth reading line by line
  - 203.0.113.5 failed 25 time(s) and then got in as root
  - 198.51.100.9 managed 16 attempts a minute for 1 minute
  - 203.0.113.5 has 3 command(s) recorded after authenticating
```

## Reading it

**The header** counts the files, the lines, how many lines were recognised, and the window the log covers. If unrecognised lines are climbing, the log has a shape this tool has not seen, and the report names the first one so you can look at it.

**The table** is one row per source address, busiest first, with a one line verdict: got in, got in after failures, or never got in at all.

**The narrative** per address is the part worth reading. It covers the window the address was active, how many connections it opened, the usernames it tried with counts, the moment it got in, the commands recorded afterwards, and any account it touched.

**What stands out** is short on purpose. A report where the alarming line is buried under someone else's port scan is a report nobody finishes.

## How a line gets attributed to an address

Grouping is by address and source port, because sshd logs the port it was talking to. On a machine under attack that port identifies one TCP connection, which is what makes this more than counting lines:

```
five failed passwords on port 51234, then an accepted one on the same port
    one session, and they got in on it

ten failures spread across ten ports
    ten connections, none of which completed a login
```

The lines that name no address at all are the interesting problem. `sudo` records a user, a command and a time, and no address. `useradd` records the account being created and not who created it. There is nothing on those lines to group by, so:

  - a `sudo` line is placed on the address that authenticated as the account it names, and has not been succeeded by another address since
  - an account change is placed on the session that was open at that moment, which is an inference and is treated as one
  - a line that cannot be placed either way is counted as orphaned and reported, rather than handed to whoever logged in last

That last case matters more than it sounds. On a busy machine the honest answer is often "nothing ties this command to a connection", and a tool that guesses anyway produces a report that reads well and is wrong.

## What it recognises

  - **sshd**: failed passwords for valid and invalid users, invalid user probes, accepted password and accepted publickey, sessions opening and closing, disconnects, connections closed before or during login, and giving up after too many attempts
  - **pam**: authentication failures for sshd, including the summary line pam writes after several of them
  - **sudo**: the account, the tty, the working directory and the command line
  - **account tools**: useradd, usermod, userdel, groupadd, groupmod, groupdel, passwd

Both timestamp shapes are read: the syslog form, which carries no year, and the ISO 8601 form that `journalctl -o short-iso` writes. A syslog log takes its year from `--year`, or from today when you do not say, so a log that spans New Year is worth passing `--year` explicitly.

## What it will not do

  - **It does not verify anything.** A log is a claim by the machine that wrote it. An attacker with root can edit it, and this tool reads what is there.
  - **It does not correlate with other artifacts.** Login events only. A file's timestamps, a process tree or a shell history would each be a different tool, and joining them is a bigger job than this.
  - **It does not read a live journal.** Export first with `journalctl -o short-iso`, then read the export. Reading `/var/log/journal` directly would mean linking a journal parser for one log source.
  - **It does not decide anything for you.** It counts, it reconstructs, and it points at a few things.

## Options

```
-n, --top N          sources to print in full, default 10
--source ADDRESS     print only that address
--year N             the year for syslog lines, which do not carry one
--json               the same reconstruction as JSON
```

## Exit codes

```
0  a report was printed
1  the files were readable but held no log lines
2  a file could not be read, or the options made no sense
```

The middle one matters when running over a directory of rotated logs: a file with nothing in it is a different problem from a file that is not there.

## Testing

```
bash tests/run-tests.sh
```

Ninety two tests across four modules, covering the line reader, the reconstruction, the report and the command line. There is no recorded log anywhere in the repository. Every test builds its own lines through `tests/log_builder.py`, so the patterns are checked against the shapes sshd and sudo really produce rather than against this tool's own output.

## How the code is laid out

```
authlogsessions/parse.py      lines into events, and the two timestamp shapes
authlogsessions/sessions.py   events into connections, connections into sources
authlogsessions/report.py     counting, and the text of the report
authlogsessions/cli.py        argument handling and printing
tests/                        the suite, and the log builder it uses
examples/                     a script that writes a log to look at
```

A line that parses into nothing is kept as an unrecognised event rather than dropped. Counting what a parser could not read is how you find out the parser is wrong.

## License

MIT. See LICENSE.
