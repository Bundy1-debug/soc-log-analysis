"""
Generate samples/host_privilege.log — fake lab auth.log for the host/privilege pack (Pack 3).

  bob      3 failed sudo (wrong password), then "user NOT in sudoers"  -> sudo abuse
  eve      4 failed su to root                                          -> su brute force
  attacker useradd + added to the sudo group                           -> new account + priv grant
  alice    one normal successful sudo                                   -> must stay quiet
"""

from datetime import datetime, timedelta
from pathlib import Path

lines = []
t = datetime(2024, 3, 22, 14, 0, 0)


def log(proc, msg, pid=1000):
    global t
    t += timedelta(seconds=5)
    lines.append(f"{t:%b %d %H:%M:%S} ubuntu {proc}[{pid}]: {msg}")


for _ in range(3):
    log("sudo", "   bob : 1 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow")
log("sudo", "   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su")

for _ in range(4):
    log("su", "FAILED su for root by eve")

log("useradd", "new user: name=svc_backup, UID=1050, GID=1050, home=/home/svc_backup, shell=/bin/bash")
log("usermod", "add 'svc_backup' to group 'sudo'")

log("sudo", "   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")

out = Path(__file__).resolve().parent / "host_privilege.log"
out.write_text("\n".join(lines) + "\n")
print(f"wrote {len(lines)} lines to {out}")
