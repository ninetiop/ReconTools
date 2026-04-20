"""Contains the YAMLConfigParser class to load configuration from a YAML file."""

# utils/yaml_config.py
from enum import Enum
from pathlib import Path

import yaml


class YAMLSection(Enum):
    """Enum class for YAML configuration sections."""

    RECON = "RECON"


class YAMLThirdParty(Enum):
    """Enum class for YAML configuration thirdparty"""

    VT = "VT"
    CERTSPOTTER = "CERTSPOTTER"
    CRTSH = "CRTSH"


class YAMLConfigParser:
    """Simple parser YAML to load configuration sections as dictionaries."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"YAML file not found: {path}")

        with open(self.path, "r", encoding="utf-8") as f:
            self._data = yaml.safe_load(f)

    def get_section(self, section: YAMLSection) -> dict:
        """Get a specific section from the YAML configuration as a dictionary."""
        key = section.value
        if key not in self._data:
            raise KeyError(f"Section '{key}' not found in YAML")
        return self._data[key]

    def get_third_party(self, third_party: YAMLThirdParty) -> dict:
        """Get a specific section from the YAML configuration as a dictionary."""
        key = third_party.value
        if key not in self._data:
            raise KeyError(f"Third-party '{key}' not found in YAML")
        return self._data[key]
