"""
MCP client — async wrapper over the IDA Pro MCP HTTP endpoint.

The IDA plugin (ida_mcp.py) runs inside IDA Pro 8.3 at localhost:13337
and accepts MCP JSON-RPC 2.0 calls at POST /mcp.

Request format:
  {"jsonrpc": "2.0", "method": "tools/call",
   "params": {"name": "<tool>", "arguments": {...}}, "id": <int>}

Response format:
  {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "..."}]}, "id": <int>}
  or
  {"jsonrpc": "2.0", "error": {"code": ..., "message": "..."}, "id": <int>}
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional
import itertools

import httpx

log = logging.getLogger(__name__)

_id_counter = itertools.count(1)
_DEFAULT_TIMEOUT = 30.0


class McpError(Exception):
    """Raised when the IDA MCP server returns an error."""


class McpClient:
    """
    Async client for the IDA Pro MCP plugin HTTP server.

    Usage::

        async with McpClient("http://localhost:13337") as client:
            funcs = await client.list_functions()
    """

    def __init__(self, base_url: str = "http://localhost:13337", timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "McpClient":
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http:
            await self._http.aclose()

    # ------------------------------------------------------------------
    # Low-level JSON-RPC 2.0 call  →  POST /mcp
    # ------------------------------------------------------------------

    async def call(self, tool_name: str, **arguments: Any) -> Any:
        """
        Call an IDA MCP tool and return its parsed result value.

        The MCP result is {"content": [{"type": "text", "text": "<json>"}]}.
        We parse the text content and return the Python object.
        """
        assert self._http, "Use as async context manager"
        request_id = next(_id_counter)
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": request_id,
        }
        log.debug("→ MCP %s %s", tool_name, arguments)

        resp = await self._http.post("/mcp", content=json.dumps(payload))
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            raise McpError(f"{tool_name}: {data['error']['message']}")

        result = data.get("result", {})
        # MCP wraps output in content list
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            raw = content[0]["text"]
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return raw  # Return as plain string if not JSON
        return result

    # ------------------------------------------------------------------
    # IDA session (idalib / headless mode only)
    # Not needed when using the IDA GUI plugin — session_id is ignored.
    # ------------------------------------------------------------------

    async def open_binary(self, path: str, session_id: Optional[str] = None) -> dict:
        """Open a binary. Returns {"session_id": ...} in idalib mode."""
        kwargs: dict[str, Any] = {"input_path": path}
        if session_id:
            kwargs["session_id"] = session_id
        result = await self.call("idalib_open", **kwargs)
        if isinstance(result, dict):
            return result
        # IDA plugin mode: no session concept, return dummy
        return {"session_id": None}

    async def close_session(self, session_id: str) -> None:
        await self.call("idalib_close", session_id=session_id)

    # ------------------------------------------------------------------
    # Analysis queries
    # ------------------------------------------------------------------

    async def list_functions(self, session_id: Optional[str] = None) -> list[dict]:
        """Returns list of {address, name, size} dicts."""
        kwargs = _sid(session_id)
        result = await self.call("list_funcs", **kwargs)
        if isinstance(result, list):
            return result
        # Some versions return {"functions": [...]}
        if isinstance(result, dict):
            return result.get("functions", [])
        return []

    async def decompile(self, address: int, session_id: Optional[str] = None) -> str:
        kwargs = {"address": hex(address), **_sid(session_id)}
        result = await self.call("decompile_function", **kwargs)
        if isinstance(result, dict):
            return result.get("code", result.get("decompilation", ""))
        return str(result) if result else ""

    async def get_disasm(self, address: int, session_id: Optional[str] = None) -> str:
        kwargs = {"address": hex(address), **_sid(session_id)}
        result = await self.call("get_function_assembly", **kwargs)
        if isinstance(result, dict):
            return result.get("assembly", result.get("asm", ""))
        return str(result) if result else ""

    async def get_callees(self, address: int, session_id: Optional[str] = None) -> list[dict]:
        kwargs = {"address": hex(address), **_sid(session_id)}
        result = await self.call("get_xrefs_from", **kwargs)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("xrefs", [])
        return []

    async def get_stack_frame(self, address: int, session_id: Optional[str] = None) -> list[dict]:
        kwargs = {"address": hex(address), **_sid(session_id)}
        result = await self.call("get_stack_variables", **kwargs)
        return result if isinstance(result, list) else []

    async def get_imports(self, session_id: Optional[str] = None) -> list[dict]:
        result = await self.call("list_imports", **_sid(session_id))
        return result if isinstance(result, list) else []

    async def get_exports(self, session_id: Optional[str] = None) -> list[dict]:
        result = await self.call("list_exports", **_sid(session_id))
        return result if isinstance(result, list) else []

    async def get_strings(self, session_id: Optional[str] = None) -> list[dict]:
        result = await self.call("list_strings", **_sid(session_id))
        return result if isinstance(result, list) else []

    async def get_structs(self, session_id: Optional[str] = None) -> list[dict]:
        result = await self.call("list_structs", **_sid(session_id))
        return result if isinstance(result, list) else []

    async def infer_types(self, address: int, session_id: Optional[str] = None) -> dict:
        kwargs = {"address": hex(address), **_sid(session_id)}
        result = await self.call("get_function_prototype", **kwargs)
        return result if isinstance(result, dict) else {}


def _sid(session_id: Optional[str]) -> dict:
    """Helper: include session_id kwarg only if set (idalib mode)."""
    return {"session_id": session_id} if session_id else {}
