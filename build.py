#!/usr/bin/env python3
"""Embed limitlessh.py and limitlessh-report.py into the installer template."""
import os

tpl = open("install-limitlessh.template.sh").read()
for marker, src_name, eof in (("@@LIMITLESSH_PY@@", "limitlessh.py", "LIMITLESSH_PY_EOF"),
                              ("@@LIMITLESSH_REPORT_PY@@", "limitlessh-report.py", "LIMITLESSH_REPORT_EOF")):
    src = open(src_name).read()
    assert eof not in src, "%s contains its heredoc terminator" % src_name
    assert tpl.count(marker) == 1, marker
    tpl = tpl.replace(marker, src.rstrip("\n"))
open("install-limitlessh.sh", "w").write(tpl)
os.chmod("install-limitlessh.sh", 0o755)
print("built install-limitlessh.sh (%d lines)" % tpl.count("\n"))
