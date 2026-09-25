"""Tests for API endpoints."""

import os
import sys
from unittest.mock import patch, AsyncMock

import pytest
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app
from app.database import init_db


@pytest.fixture(autouse=True)
async def setup_db():
    """Initialize database tables before each test."""
    await init_db()


@pytest.mark.asyncio
async def test_health_endpoint():
    """Test health check returns ok."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_list_analyses_empty():
    """Test listing analyses when none exist."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/analyses")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_get_nonexistent_analysis():
    """Test getting a non-existent analysis returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/analyses/nonexistent-uuid")

    assert response.status_code == 404
