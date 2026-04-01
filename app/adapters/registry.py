"""
Adapter registry for managing vulnerability scanner implementations.

This module provides a central registry where all scanner adapters are stored
and retrieved by name. It allows the application to dynamically select which
scanner to use for a given scan request.
"""

from dotenv import load_dotenv
from typing import Dict
from app.adapters.base import BaseAdapter

# Load environment variables from local .env file on startup too
load_dotenv()


class AdapterRegistry:
    """
    Holds all registered adapters by name.
    Add new adapters here as you build them.
    """

    def __init__(self):
        self._adapters: Dict[str, BaseAdapter] = {}  # Dictionary mapping adapter names to instances

    def register(self, adapter: BaseAdapter) -> None:
        """Register a new adapter instance with the registry."""
        self._adapters[adapter.name] = adapter
        print(f"[registry] registered adapter: {adapter.name}")  # Log successful registration

    def get(self, name: str) -> BaseAdapter:
        """Retrieve an adapter by its registered name."""
        adapter = self._adapters.get(name)
        if not adapter:
            raise KeyError(f"No adapter registered with name '{name}'. "
                           f"Available: {list(self._adapters.keys())}")
        return adapter

    def available(self):
        """Return a list of all registered adapter names."""
        return list(self._adapters.keys())


# Single shared registry instance used across the application
registry = AdapterRegistry()
