#!/usr/bin/env python3
"""Embed limitlessh.py into the installer template -> install-limitlessh.sh"""
import os, stat
src = open("limitlessh.py").read()
assert "LIMITLESSH_PY_EOF" not in src
tpl = open("install-limitlessh.template.sh").read()
assert tpl.count("@@LIMITLESSH_PY@@") == 1
out = tpl.replace("@@LIMITLESSH_PY@@", src.rstrip("\n"))
open("install-limitlessh.sh", "w").write(out)
os.chmod("install-limitlessh.sh", 0o755)
print("built install-limitlessh.sh (%d lines)" % out.count("\n"))
