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
        recon_section = parser.get_section(YAMLSection.RECON)
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
        base_url = "https://crt.sh/?q={}&output=json"
        domain = f"%.{self.domain}" if not self.domain.startswith("%") else self.domain

        url = base_url.format(domain)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko Firefox/40.1"
        }
        logger.info(f"[+] Querying crt.sh API with URL: {url}")
        r = requests.get(url, headers=headers, timeout=30)

        if not r.ok:
            logger.warning(f"[!] Failed to query crt.sh API for domain: {self.domain}")
            return set()

        try:
            data = r.json()
        except Exception:
            content = r.text
            data = json.loads("[" + content.replace("}{", "},{") + "]")

        subdomains = set()

        for d in data:
            for sub in d.get("name_value", "").split("\n"):
                sub = sub.strip().lower()

                if sub.startswith("*."):
                    sub = sub[2:]

                subdomains.add(sub)

        logger.info(f"[+] Found {len(subdomains)} subdomains for domain: {self.domain}")
        return subdomains
