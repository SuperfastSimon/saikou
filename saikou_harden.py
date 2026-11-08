"""Compatibility shim: the engine now lives in the `saikou` package.

Kept so existing callers keep working:
    import saikou_harden as s; s.scan_transformation(...)
    python saikou_harden.py --selftest
    uvicorn saikou_harden:app        (needs `pip install saikou[api]`)

New code should use `import saikou` or the `saikou` command.
"""

import os as _os
import sys as _sys

_here = _os.path.dirname(_os.path.abspath(__file__))
if _here not in _sys.path:
    _sys.path.insert(0, _here)

from saikou import engine as _engine

globals().update({k: v for k, v in vars(_engine).items()
                  if not (k.startswith("__") and k.endswith("__")) or k == "__version__"})

try:
    from saikou.api import app
except ImportError:  # FastAPI not installed: the engine is still fully usable
    pass

if __name__ == "__main__":
    if "--selftest" in _sys.argv:
        raise SystemExit(_engine._selftest())
    print(__doc__)
