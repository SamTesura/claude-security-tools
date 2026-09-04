"""Test bootstrap for the security MCP server.

The module runs `_load_scope()` and `init_storage()` at import time. We point
storage at a throwaway temp dir and default scope to audit mode so the import
succeeds; individual scope tests switch the module into enforce mode against a
temporary scope file.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="mcp-sec-test-")
os.environ["RESULTS_PATH"] = os.path.join(_TMP, "results")
os.environ["SCAN_DB_PATH"] = os.path.join(_TMP, "scans.db")
os.environ.setdefault("MCP_SCOPE_MODE", "audit")
