"""`python -m bonelia.server …` = `bonelia-server …`.

The Windows scripts start the server this way: pip's generated bonelia-server.exe is unsigned and is
rebuilt on every update, and Windows Smart App Control blocks it (seen 06.11.2026); the signed
python.exe is allowed."""

import sys

from .cli import main

sys.exit(main())
