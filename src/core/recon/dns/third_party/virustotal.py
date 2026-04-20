import logging
from pathlib import Path

import requests
from utils.yaml_config import YAMLConfigParser, YAMLSection

logger = logging.getLogger(__name__)


class VirusTotal:
    """Client for VirusTotal API to retrieve subdomains."""

    def __init__(self, domain: str) -> None:
        """Initialize the VirusTotal client.

        Args:
            domain: The target domain to query.
        """
        self._domain = domain
        config_dir = Path(__file__).parents[5] / "config"
        parser = YAMLConfigParser(config_dir / "config.yaml")
        recon_section = parser.get_section(YAMLSection.RECON)  # retourne un dict
        third_party = recon_section["THIRD_PARTY"]  # maintenant c'est un dict
        self._config = third_party["VT"]

    @property
    def domain(self):
        """Get the target domain."""
        return self._domain

    @property
    def config(self):
        """Get the VirusTotal configuration."""
        return self._config

    def get_subdomains(self, limit: int = 40):
        """Fetch subdomains from VirusTotal API.

        Args:
            limit: Maximum number of subdomains to retrieve.

        Returns:
            Set of subdomains found.
        """
        url = f"{self.config['URL']}/{self.domain}/relationships/subdomains"
        payload = {"limit": limit}
        headers = {"x-apikey": f"{self.config['API_KEY']}"}
        logging.info("[+] Trying to fetch subdomains from VirusTotal platform")
        r = requests.get(url, headers=headers, params=payload)
        r.raise_for_status()
        data = r.json()["data"]
        return set(sub["id"] for sub in data)
