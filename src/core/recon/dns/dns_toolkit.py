"""DNS Toolkit for reconnaissance operations.

Provides unified interface for DNS enumeration including:
- DNS record enumeration (A, AAAA, CNAME, NS, MX, TXT)
- Subdomain enumeration using wordlists and third-party sources
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from core.recon.dns.third_party.engine import ThirdPartyEngine
from dns.resolver import Resolver

logger = logging.getLogger(__name__)


class DNSToolkit:
    """Unified DNS enumeration toolkit.

    Combines DNS record and subdomain enumeration capabilities with a
    consistent interface and shared configuration.
    """

    def __init__(self, resolvers: List[str] | None = None) -> None:
        """Initialize the DNS Toolkit.

        Args:
            domain: Target domain/host to enumerate.
            resolvers: List of DNS resolver IP addresses.
                      Defaults to CloudFlare (1.1.1.1) and Google (8.8.8.8).
        """
        self._resolvers = resolvers if resolvers else ["1.1.1.1", "8.8.8.8"]
        self._resolver = self._setup_resolver()

        # DNS records configuration
        self._records_type = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

        # Subdomain enumeration
        self._wordlist: Optional[List[str]] = None

    def _setup_resolver(self) -> Resolver:
        """Setup DNS resolver with configured nameservers.

        Returns:
            Configured Resolver instance.
        """
        resolver = Resolver()
        resolver.nameservers = self._resolvers
        resolver.timeout = 0.5
        resolver.lifetime = 3
        return resolver

    @property
    def resolvers(self) -> List[str]:
        """Get the list of configured resolvers."""
        return self._resolvers

    @property
    def resolver(self) -> Resolver:
        """Get the DNS resolver instance."""
        return self._resolver

    @property
    def records_type(self) -> List[str]:
        """Get the list of supported DNS record types."""
        return self._records_type

    @property
    def wordlist(self) -> List[str] | None:
        """Get the loaded wordlist."""
        return self._wordlist

    def _load_wordlist(self, wordlist: str | None = None) -> None:
        """Load and deduplicate wordlist from file.

        Args:
            wordlist: Path to the wordlist file.

        Returns:
            List of unique subdomain prefixes.
        """
        if wordlist:
            with open(wordlist, "r") as f:
                self._wordlist = list(set(line.strip() for line in f if line.strip()))
            f.close()

    def _resolve(self, fqdn: str):
        try:
            ret = {"fqdn": fqdn, "A": set(), "AAAA": set(), "CNAME": set()}

            for record_type in ["A", "AAAA", "CNAME"]:
                try:
                    answers = self.resolver.resolve(fqdn, record_type)

                    if record_type == "CNAME":
                        values = [str(r.target).rstrip(".") for r in answers]
                    else:
                        values = [str(r) for r in answers]

                    ret[record_type].update(values)

                    logger.info(f"[+] {fqdn} → {record_type}: {values}")

                except Exception:
                    pass

            if not (ret["A"] or ret["AAAA"] or ret["CNAME"]):
                return None

            return ret

        except Exception:
            return None

    def enum_dns_records(self, domain: str, record_types: List[str]) -> dict:
        """Enumerate DNS records for the domain.

        Args:
            domain: The target domain.
            record_types: List of record types to query (e.g., ['A', 'MX', 'TXT']).

        Returns:
            Dict mapping record types to lists of resolved values.
        """
        result = {}
        for record in record_types:
            logger.info(f"[+] Trying to resolve {record} records for {domain}...")
            if record in self.records_type:
                try:
                    result[record] = [
                        str(value).strip('"')
                        for value in self.resolver.resolve(domain, record)
                    ]
                except Exception:
                    result[record] = []
        return result

    def enum_subdomains(
        self, domain: str, wordlist: Optional[str] = None, nb_threads: int = 150
    ) -> list:
        """Enumerate subdomains for the domain.

        Supports both wordlist-based brute force and third-party sources
        (certificate transparency logs, etc.).

        Args:
            domain: The target domain.
            wordlist: Optional path to wordlist file for brute force enumeration.
                     If not provided, only third-party sources are used.
            nb_threads: Number of worker threads for concurrent resolution.

        Returns:
            Set of subdomains found.
        """
        # Load wordlist if provided
        self._load_wordlist(wordlist)
        engine = ThirdPartyEngine()
        subdomains = engine.get_subdomains(domain)
        subdomains_resolvable = dict()
        for sub in subdomains:
            res = self._resolve(sub)
            if res:
                subdomains_resolvable[res["fqdn"]] = res
        return subdomains_resolvable
