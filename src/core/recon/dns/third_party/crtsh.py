import json
import logging
from pathlib import Path

import requests
from utils.yaml_config import YAMLConfigParser, YAMLSection

logger = logging.getLogger(__name__)


class CrtSh:
    """Client for crt.sh API to retrieve SSL certificates and subdomains."""

    def __init__(self, domain: str) -> None:
        """Initialize the CrtSh client.

        Args:
            domain: The target domain to query.
        """
        self._domain = domain
        config_dir = Path(__file__).parents[5] / "config"
        parser = YAMLConfigParser(config_dir / "config.yaml")
        recon_section = parser.get_section(YAMLSection.RECON)  # retourne un dict
        third_party = recon_section["THIRD_PARTY"]
        self._config = third_party["CRTSH"]

    @property
    def domain(self):
        """Get the target domain."""
        return self._domain

    @property
    def config(self):
        """Get the CrtSh configuration."""
        return self._config

    def get_subdomains(self):
        """Fetch subdomains from crt.sh API.

        Returns:
            Set of subdomains found in certificates.
        """
        url = self.config["URL"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
            "Accept": "application/json",
        }
        payload = {"q": f"{self.domain}", "output": "json"}
        logger.info("[+] Trying to fetch subdomain from Crtsh platform")
        r = requests.get(url, params=payload, headers=headers)
        r.raise_for_status()

        data = json.loads(r.text)
        subdomains = set()

        for d in data:
            names = d.get("name_value", "")

            for sub in names.split("\n"):
                sub = sub.strip().lower()

                if sub.startswith("*."):
                    sub = sub[2:]

                if sub.endswith(f".{self.domain}") or sub == self.domain:
                    subdomains.add(sub)

        return subdomains
