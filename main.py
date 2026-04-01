"""
Main FastAPI application for the moku-analyzer service.

This file sets up the FastAPI web application and registers all available
vulnerability scanner adapters. It serves as the entry point for the web service
that provides REST API endpoints for vulnerability scanning.
"""

from fastapi import FastAPI
from app.api.routes import router
from app.adapters.registry import registry
from app.adapters.builtin_adapter import BuiltinAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.mock_adapter import MockAdapter

# Create the main FastAPI application instance
# This sets up the web server with basic metadata
app = FastAPI(
    title="moku-analyzer",
    description="Vulnerability analyzer service for the moku platform",
    version="0.1.0",
)

# ── register adapters ─────────────────────────────────────────────────────────
# Register all available vulnerability scanner adapters with the registry
# Each adapter provides a different scanning capability (nuclei, nikto, etc.)
# Add new adapters here as you build them
registry.register(BuiltinAdapter())  # Basic placeholder adapter
registry.register(NucleiAdapter())   # Nuclei vulnerability scanner
registry.register(NiktoAdapter())    # Nikto web server scanner
registry.register(MockAdapter())     # Mock adapter for testing

# ── mount routes ──────────────────────────────────────────────────────────────
# Include the API routes from the routes module
# This adds all the REST API endpoints (/scan, /health, etc.) to the app
app.include_router(router)
