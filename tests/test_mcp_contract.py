"""
MCP contract tests — run against a live idalib-mcp endpoint.

Skip unless RESOURCE_MCP_ENDPOINT env var is set.
"""
import os
import pytest
import asyncio

pytestmark = pytest.mark.skipif(
    not os.environ.get("RESOURCE_MCP_ENDPOINT"),
    reason="Set RESOURCE_MCP_ENDPOINT to run MCP contract tests",
)

ENDPOINT = os.environ.get("RESOURCE_MCP_ENDPOINT", "http://localhost:13337")
TEST_BINARY = os.environ.get("RESOURCE_TEST_BINARY", "")


@pytest.fixture
async def client():
    from app.mcp.client import McpClient
    async with McpClient(ENDPOINT) as c:
        yield c


async def test_open_binary(client):
    assert TEST_BINARY, "Set RESOURCE_TEST_BINARY"
    result = await client.open_binary(TEST_BINARY)
    assert "session_id" in result


async def test_list_functions(client):
    result = await client.list_functions()
    assert isinstance(result, list)
    if result:
        assert "address" in result[0]
        assert "name" in result[0]


async def test_decompile_first_function(client):
    funcs = await client.list_functions()
    if not funcs:
        pytest.skip("No functions found")
    addr = funcs[0]["address"]
    code = await client.decompile(addr)
    assert isinstance(code, str)
    assert len(code) > 0
