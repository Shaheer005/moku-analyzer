"""Tests for the Adapter Registry."""

import pytest
from app.adapters.registry import AdapterRegistry
from app.adapters.base import BaseAdapter
from typing import List
from app.models.schemas import Vulnerability


class DummyAdapter(BaseAdapter):
    """Dummy adapter for testing."""
    name = "dummy"
    description = "A dummy adapter"

    def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
        return []

    def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
        return []


class AnotherAdapter(BaseAdapter):
    """Another dummy adapter."""
    name = "another"
    description = "Another dummy adapter"

    def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
        return []

    def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
        return []


class TestRegistry:
    """Test AdapterRegistry operations."""

    def setup_method(self):
        """Create a fresh registry for each test."""
        self.registry = AdapterRegistry()

    def test_register_and_get(self):
        """Registering an adapter should make it retrievable."""
        adapter = DummyAdapter()
        self.registry.register(adapter)
        
        retrieved = self.registry.get("dummy")
        assert retrieved is not None
        assert retrieved.name == "dummy"

    def test_get_unknown_adapter_raises_keyerror(self):
        """Getting a non-existent adapter should raise KeyError."""
        with pytest.raises(KeyError):
            self.registry.get("nonexistent")

    def test_available_returns_list(self):
        """available() should return list of registered adapter names."""
        adapter1 = DummyAdapter()
        adapter2 = AnotherAdapter()
        self.registry.register(adapter1)
        self.registry.register(adapter2)
        
        names = self.registry.available()
        assert "dummy" in names
        assert "another" in names
        assert len([n for n in names if n in ["dummy", "another"]]) == 2

    def test_register_multiple_adapters(self):
        """Registering multiple adapters should work."""
        adapters = [DummyAdapter(), AnotherAdapter()]
        for adapter in adapters:
            self.registry.register(adapter)
        
        available = self.registry.available()
        assert "dummy" in available
        assert "another" in available

    def test_adapter_overwrite(self):
        """Registering an adapter with same name should overwrite."""
        adapter1 = DummyAdapter()
        self.registry.register(adapter1)
        
        # Create another adapter with same name
        class AnotherDummy(BaseAdapter):
            name = "dummy"
            description = "Modified dummy"
            def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
                return []
            def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
                return []
        
        adapter2 = AnotherDummy()
        self.registry.register(adapter2)
        
        retrieved = self.registry.get("dummy")
        assert retrieved.description == "Modified dummy"
