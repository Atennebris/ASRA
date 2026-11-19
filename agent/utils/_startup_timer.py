"""Captures the wall-clock moment this module is first imported. Meant to be the very FIRST import
in main.py, before any of its other (much heavier) imports run, so main.py's own _lifespan can log
how long its whole import graph actually took -- confirmed real incident: a desktop-shell launch
logged "waited 95200ms for backend port 8000 to come up" with nothing anywhere breaking down where
that time actually went. A separate module instead of an inline assignment inside main.py itself
because ruff's E402 (no statement before an import) would otherwise flag every one of main.py's own
later imports as "not at top of file" -- keeping "capture a timestamp first" itself an ordinary
import statement avoids that without disabling the lint check everywhere else in the file.
"""
import time

IMPORT_START_TIME = time.time()
