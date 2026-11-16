"""Types the machine token at the hidden prompt of `bas broker install`.

`systemd-ask-password` reads the token from a terminal, so this runs the given command on a
terminal of its own. Echo is off on that terminal before the command starts, and the token
is written only after the prompt appears, so the token is never printed.

    BWS_ACCESS_TOKEN=... type-token.py sudo /path/to/bas broker install ...
"""

import os
import pty
import sys
import termios

PROMPT = b"Machine token"


def main() -> None:
    token = os.environ.pop("BWS_ACCESS_TOKEN").encode()
    pid, terminal = pty.fork()
    if pid == 0:
        settings = termios.tcgetattr(0)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, settings)
        os.execvp(sys.argv[1], sys.argv[1:])
    seen = b""
    typed = False
    while True:
        try:
            data = os.read(terminal, 4096)
        except OSError:
            break
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        seen += data
        if not typed and PROMPT in seen:
            os.write(terminal, token + b"\n")
            typed = True
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))


if __name__ == "__main__":
    main()
