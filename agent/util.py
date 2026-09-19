"""
agent/util.py — forwarding shim to the repository-root util.py.

历史上这里是根目录 util.py 的一个过时副本 (缺少 unseen 检测所需的
UNSEEN_INFO_COLS / DeepSeekFingerprintSummarizer 等符号, 且 BASE_PATH
指向 agent/ 而非仓库根目录, 导致 load_perspective_info 等 loader 找不到
perspective_info.json). 为避免两份副本再次漂移, 本文件现按路径直接加载
根目录的 util.py 并转发其全部公开符号, 使 `from util import *` 无论解析
到哪一份都得到相同且完整的模块.
Historically this file was a stale subset copy of the repository-root util.py
(missing the unseen-detection symbols and pointing BASE_PATH at agent/ instead
of the repo root). It now loads the root util.py by explicit path and
re-exports all of its public symbols, so both resolutions of `import util`
yield the same complete module.
"""

import importlib.util as _importlib_util
import os as _os

_ROOT_UTIL_PATH = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "util.py",
)

_spec = _importlib_util.spec_from_file_location("_iotprober_root_util", _ROOT_UTIL_PATH)
_root_util = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(_root_util)

for _name, _value in list(_root_util.__dict__.items()):
    if not _name.startswith("__"):
        globals()[_name] = _value

del _importlib_util, _os, _spec, _root_util, _name, _value, _ROOT_UTIL_PATH
