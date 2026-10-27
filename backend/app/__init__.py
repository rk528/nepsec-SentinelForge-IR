import os
import sys

# Some Windows machines enforce Application Control policies that block
# unsigned native extension DLLs, including SQLAlchemy's optional Cython
# speedups. SQLAlchemy works fully without them, so skip loading them on
# Windows. Linux deployments (Vercel, CI) keep the compiled extensions.
if sys.platform == "win32":
    os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT_RUNTIME", "1")
