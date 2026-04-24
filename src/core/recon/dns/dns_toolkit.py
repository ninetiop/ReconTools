"""DNS Toolkit for reconnaissance operations.

Provides unified interface for DNS enumeration including:
- DNS record enumeration (A, AAAA, CNAME, NS, MX, TXT)
- Subdomain enumeration using third-party sources
"""

import logging
from typing import List

from core.recon.dns.third_party.engine import ThirdPartyEngine
from dns.resolver import Resolver

logger = logging.getLogger(__name__)


class DNSToolkit:
    """Unified DNS enumeration toolkit.

    Combines DNS record and subdomain enumeration capabilities with a
    consistent interface and shared configuration.
    """

    RECORDS_TYPE = ["A", "MX", "TXT", "CNAME", "NS", "AAAA", "SOA", "SRV", "PTR"]
    RECORDS_RESOLVE = ["A", "AAAA", "CNAME"]

    def __init__(self, resolvers: List[str] | None = None) -> None:
        """Initialize the DNS Toolkit.

        Args:
            domain: Target domain/host to enumerate.
            resolvers: List of DNS resolver IP addresses.
                      Defaults to CloudFlare (1.1.1.1) and Google (8.8.8.8).
        """
        self._resolvers = resolvers if resolvers else ["1.1.1.1", "8.8.8.8"]
        self._resolver = self._setup_resolver()

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

    def _resolve(self, fqdn: str):
        try:
            ret = {"fqdn": fqdn, "A": set(), "AAAA": set(), "CNAME": set()}

            for record_type in self.RECORDS_RESOLVE:
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

    def enum_dns_records(self, domain: str) -> dict:
        """Enumerate DNS records for the domain.

        Args:
            domain: The target domain.

        Returns:
            Dict mapping record types to lists of resolved values.
        """
        result = {}
        for record in self.RECORDS_TYPE:
            logger.info(f"[+] Trying to resolve {record} records for {domain}...")
            try:
                result[record] = [
                    str(value).strip('"')
                    for value in self.resolver.resolve(domain, record)
                ]
            except Exception:
                result[record] = []
        return result

    def enum_subdomains(self, domain: str, nb_threads: int = 150) -> list:
        """Enumerate subdomains for the domain.

        Args:
            domain: The target domain.
            nb_threads: Number of worker threads for concurrent resolution.

        Returns:
            Set of subdomains found.
        """
        engine = ThirdPartyEngine()
        subdomains = engine.get_subdomains(domain)
        subdomains_resolvable = dict()
        for sub in subdomains:
            res = self._resolve(sub)
            if res:
                subdomains_resolvable[res["fqdn"]] = res
        return subdomains_resolvable
