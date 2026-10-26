"""Intentionally weak test fixture; never execute this file."""

import subprocess

password = "example-fixture-password"
value = eval("1 + 1")
subprocess.run("echo fixture", shell=True)
