"""把仓库根目录加入 sys.path，保证 tests 可以直接 import safetpl。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
