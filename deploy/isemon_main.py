"""isemon, started from its compiled form (1.10.270).

Python never keeps the compiled form of a file it is given to run - only of
one it imports. isemon.py run as it is was 85 000 lines compiled again at
every start: a second of the daemon's start and of every `isemon` command,
the console's too. Run from here, it is imported as `__main__` - the same
module, the same `__name__`, `__file__` and `sys.argv[0]` as when it is run as
a file - from LIB_DIR/__pycache__/, which install.sh compiles for the Python
in LIB_DIR/python (checked against the file's hash, so a changed isemon.py is
never run from an old compiled form). Without it, isemon.py is compiled here
as it always was.
"""
import runpy

runpy.run_module('isemon', run_name='__main__', alter_sys=True)
