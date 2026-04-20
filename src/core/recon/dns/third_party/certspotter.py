import logging
from pathlib import Path

import requests
from utils.yaml_config import YAMLConfigParser, YAMLSection

logger = logging.getLogger(__name__)


class CertSpotter:
    """Client for CertSpotter API to retrieve SSL certificates and subdomains."""

    def __init__(self, domain: str) -> None:
        """Initialize the CertSpotter client.

        Args:
            domain: The target domain to query.
        """
        self._domain = domain
        config_dir = Path(__file__).parents[5] / "config"
        parser = YAMLConfigParser(config_dir / "config.yaml")
        recon_section = parser.get_section(YAMLSection.RECON)
        third_party = recon_section["THIRD_PARTY"]
        self._config = third_party["CERTSPOTTER"]

    @property
    def domain(self):
        """Get the target domain."""
        return self._domain

    @property
    def config(self):
        """Get the CertSpotter configuration."""
        return self._config

    def get_subdomains(self):
        """Fetch subdomains from CertSpotter API.

        Returns:
            Set of subdomains found in certificates.
        """
        url = self.config["URL"]
        payload = {
            "domain": self.domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        headers = {"Authorization": f"Bearer {self.config['API_KEY']}"}
        logger.info("[+] Trying to fetch subdomain from CertSpotter platform")
        r = requests.get(url, params=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        return set(sub for d in data for sub in d["dns_names"])
