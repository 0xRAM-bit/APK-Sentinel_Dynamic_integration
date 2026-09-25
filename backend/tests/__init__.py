"""Test fixtures and configuration for APK Sentinel tests."""

import pytest
import os
import sys

# Add backend app to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
