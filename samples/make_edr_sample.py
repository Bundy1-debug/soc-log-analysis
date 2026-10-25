"""
Generate samples/auditd_exec.log — fake auditd records for the EDR pack (Pack 4).

These are LOG LINES only: inert strings in the auditd format, not runnable commands.
They describe, in one attacker session (auid=1001), a classic post-exploitation chain:
  reverse shell -> read /etc/shadow -> steal SSH key -> cron + authorized_keys persistence
  -> clear logs and history. Plus benign admin commands that must stay quiet.
"""

from pathlib import Path

event_id = 1000
ts = 1711100000          # fixed epoch so the sample is reproducible


def execve(argv, auid="1001", uid="1001", exe=None, key="detect"):
    """Emit the EXECVE + SYSCALL pair auditd writes for one executed command."""
    global event_id, ts
    event_id += 1
    ts += 3
    exe = exe or ("/bin/bash" if argv[0] in ("bash", "sh") else f"/usr/bin/{argv[0]}")
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return [
        f'type=EXECVE msg=audit({ts}.000:{event_id}): argc={len(argv)} {args}',
        f'type=SYSCALL msg=audit({ts}.000:{event_id}): arch=c000003e syscall=59 success=yes '
        f'exit=0 comm="{argv[0]}" exe="{exe}" key="{key}" auid={auid} uid={uid}',
    ]


lines = []
# malicious session (auid=1001)
lines += execve(["bash", "-i"], exe="/bin/bash")                                  # reverse shell shape
lines += execve(["cat", "/etc/shadow"])                                           # credential access
lines += execve(["cp", "/home/dev/.ssh/id_rsa", "/tmp/k"])                        # private key theft
lines += execve(["crontab", "-l"])                                                # cron persistence recon/edit
lines += execve(["tee", "-a", "/root/.ssh/authorized_keys"])                      # ssh key persistence
lines += execve(["systemctl", "enable", "evil.service"])                          # service persistence
lines += execve(["truncate", "-s", "0", "/var/log/auth.log"])                     # clear logs
lines += execve(["history", "-c"])                                                # clear history

# benign admin (auid=1000) — must stay quiet
lines += execve(["ls", "-la", "/var/www"], auid="1000", uid="1000", key="watch")
lines += execve(["apt", "update"], auid="1000", uid="1000", key="watch")
lines += execve(["systemctl", "status", "nginx"], auid="1000", uid="1000", key="watch")

out = Path(__file__).resolve().parent / "auditd_exec.log"
out.write_text("\n".join(lines) + "\n")
print(f"wrote {len(lines)} lines to {out}")
