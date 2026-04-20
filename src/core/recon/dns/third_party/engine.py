import logging

from core.recon.dns.third_party.certspotter import CertSpotter
from core.recon.dns.third_party.crtsh import CrtSh
from core.recon.dns.third_party.virustotal import VirusTotal

logger = logging.getLogger(__name__)


class ThirdPartyEngine:
    """Engine for collecting subdomains from multiple third-party sources.

    Integrates CertSpotter, CrtSh, and VirusTotal for comprehensive subdomain enumeration.
    """

    def __init__(self) -> None:
        """Initialize the Engine instance."""

    def get_subdomains(self, domain: str):
        """Retrieve subdomains from all configured engines.

        Returns:
            Set of unique subdomains found.
        """
        subdomains = set()
        for engine in [
            CertSpotter(domain),
            CrtSh(domain),
            VirusTotal(domain),
        ]:
            try:
                subdomains.update(engine.get_subdomains())
            except Exception as exc:
                logger.warning(
                    f"Failed to fetch subdomain from {engine.__class__.__name__}: {exc}"
                )
        return subdomains
