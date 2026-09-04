"""
demo/capture/session_log.py
Timestamps every [KEM]/[SEC]/[TX]/[RX]/[DROP]/[ALERT] event and tees it to
demo/logs/demo_session_<timestamp>.log.

That log file is the evidence behind the measured figures in the final
report's §7 -- without it those numbers are recollections.

STUB -- Phase IX. Wraps send.py / recv.py output streams once they exist.
"""

import datetime
import os
import re
import sys

EVENT = re.compile(r"^\[(KEM|SEC|TX|RX|DROP|ALERT)\]")


def log_path(directory="demo/logs"):
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(directory, f"demo_session_{stamp}.log")


def tee(stream_in, path):
    """Read lines, stamp recognised events, write to both stdout and the log."""
    with open(path, "a", encoding="utf-8") as fh:
        for line in stream_in:
            line = line.rstrip("\n")
            if EVENT.match(line):
                line = f"{datetime.datetime.now().isoformat(timespec='milliseconds')}  {line}"
            print(line)
            fh.write(line + "\n")
            fh.flush()


if __name__ == "__main__":
    p = log_path()
    print(f"[session_log] writing to {p}", file=sys.stderr)
    tee(sys.stdin, p)
