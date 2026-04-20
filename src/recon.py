"""
Recon Toolkit CLI

A comprehensive command-line interface for reconnaissance operations, focusing on DNS enumeration and subdomain discovery.

Features:
- DNS record enumeration (A, MX, TXT, CNAME, NS, AAAA, SOA, SRV, PTR)
- Subdomain enumeration using third-party sources
- HTTP probing of discovered subdomains for status and technology detection
- Support for custom DNS resolvers
- JSON/CSV output for integration with other tools

Commands:
- enum_records: Enumerate DNS records for a given domain
- enum_subdomains: Discover subdomains using third-party sources and probe their HTTP status

Usage:
    python recon.py enum_records example.com -p
    python recon.py enum_records example.com -o results.txt
    python recon.py enum_subdomains example.com --json -o results.json

Options:
    --doc: Display this documentation
    --help: Show help for commands
    -o, --output: Write results to specified file
    -p, --pretty: Display results in human-readable format
    -j, --json: Output results in JSON format

Future enhancements: port scanning, service detection, and more reconnaissance techniques.
"""

import asyncio
import json
import logging

import click
from core.recon.dns.dns_toolkit import DNSToolkit
from core.recon.http.http_toolkit import HTTPToolkit
from tabulate import tabulate
from utils.banner import print_banner
from utils.logger import setup_logger

setup_logger()
logger = logging.getLogger(__name__)

DNS_RECORD_TYPES = ["A", "MX", "TXT", "CNAME", "NS", "AAAA", "SOA", "SRV", "PTR"]


# -------------------------
# Formatter functions
# -------------------------
def format_records(records, as_json: bool, pretty: bool):
    """Format DNS record results for output"""
    if as_json:
        return json.dumps(records, indent=2)

    lines = [(rtype, value) for rtype, vals in records.items() for value in vals]

    if pretty:
        # tabulate fait le rendu “table” joli automatiquement
        return tabulate(lines, headers=["TYPE", "VALUE"], tablefmt="grid")

    return "TYPE,VALUE\n" + "\n".join(f"{rtype},{value}" for rtype, value in lines)


def format_subdomains_register(status_subdomains: set, as_json: bool, pretty: bool):
    """Format subdomain enumeration results for output"""
    if as_json:
        result_json = [
            {k: list(v) if isinstance(v, set) else v for k, v in d.items()}
            for d in status_subdomains.values()
        ]
        return json.dumps(result_json, indent=2)
    rows = []
    for subdomain, status_subdomain in status_subdomains.items():
        fqdn = status_subdomain.get("fqdn")
        web_server = status_subdomain.get("web-server", "None")
        web_waf = status_subdomain.get("web-waf", "None")
        waf_cf_ray = status_subdomain.get("waf-cf-ray", "None")
        https_status = status_subdomain.get("https_status", "Unreachable")
        http_status = status_subdomain.get("http_status", "Unreachable")
        rows.append((fqdn, web_server, web_waf, waf_cf_ray, http_status, https_status))
    if pretty:
        return tabulate(
            rows,
            headers=[
                "FQDN",
                "WEB_SERVER",
                "WEB_WAF",
                "WAF_CF_RAY",
                "HTTP_STATUS",
                "HTTPS_STATUS",
            ],
            tablefmt="grid",
        )

    # Sortie CSV pour pipeline
    return "FQDN,WEB_SERVER,WEB_WAF,WAF_CF_RAY,HTTP_STATUS,HTTPS_STATUS\n" + "\n".join(
        f"{fqdn},{web_server},{web_waf},{waf_cf_ray},{http_status},{https_status}"
        for fqdn, web_server, web_waf, waf_cf_ray, http_status, https_status in rows
    )


def output_result(content: str, output_file: str | None):
    """Write content to file if needed and always print to stdout"""
    if output_file:
        with open(output_file, "w") as f:
            f.write(content)
        logger.info(f"Results written to {output_file}")
    print(content)


# -------------------------
# CLI commands
# -------------------------
@click.group(invoke_without_command=True)
@click.option("--doc", is_flag=True, help="Display module docstring")
def cli(doc):
    """Recon Toolkit CLI: multi-services DNS, HTTP, Ports."""
    if doc:
        print(__doc__)
        return
    ctx = click.get_current_context()
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())
        ctx.exit()
    print_banner()


@cli.command("enum_records")
@click.argument("domain")
@click.option(
    "--type-records",
    "-t",
    multiple=True,
    default=["A", "MX", "TXT", "CNAME", "NS", "AAAA", "SOA", "SRV", "PTR"],
    help="List of DNS record types to query",
)
@click.option("--resolvers", "-r", multiple=True, help="Resolver's IP DNS")
@click.option(
    "--json",
    "-j",
    "as_json",
    is_flag=True,
    default=False,
    help="Output results as JSON",
)
@click.option("--output", "-o", help="Output file to write results to")
@click.option(
    "--pretty",
    "-p",
    is_flag=True,
    default=False,
    help="Display result as human-readable",
)
def enum_records(
    domain: str,
    as_json: bool,
    type_records: list[str],
    resolvers: list[str],
    output: str | None,
    pretty: bool,
):
    """Enumerate DNS records"""
    if as_json and pretty:
        raise click.UsageError("--pretty and --json cannot be used together")

    toolkit = DNSToolkit(resolvers=resolvers)
    records = toolkit.enum_dns_records(domain, type_records)

    content = format_records(records, as_json, pretty)
    output_result(content, output)


@cli.command("enum_subdomains")
@click.argument("domain")
@click.option("--resolvers", "-r", multiple=True, help="Resolver's IP DNS")
@click.option(
    "--wordlist",
    "-w",
    default=None,
    help="Optional wordlist of subdomain to enumerate on target. "
    "If not provided, uses third-party sources.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False, help="Output results as JSON"
)
@click.option("--output", "-o", type=str, help="Save result in file")
@click.option(
    "--pretty",
    "-p",
    is_flag=True,
    default=False,
    help="Display result as human-readable",
)
def enum_subdomains(
    domain: str,
    resolvers: list[str],
    wordlist: str | None,
    as_json: bool,
    output: str | None,
    pretty: bool,
):
    """Enumerate DNS subdomains"""
    asyncio.run(_enum_subdomains(domain, resolvers, wordlist, as_json, output, pretty))


async def _enum_subdomains(
    domain: str,
    resolvers: list[str],
    wordlist: str | None,
    as_json: bool,
    output: str | None,
    pretty: bool,
):
    """Enumerate DNS subdomains"""
    if as_json and pretty:
        raise click.UsageError("--pretty and --json cannot be used together")

    dns_toolkit = DNSToolkit(resolvers=resolvers)
    http_toolkit = HTTPToolkit()

    subdomains_registers = dns_toolkit.enum_subdomains(domain, wordlist)
    subdomains_status = {}
    async for status_probe in http_toolkit.probe(subdomains_registers):
        if status_probe:
            subdomains_status[status_probe["fqdn"]] = status_probe
    if subdomains_status:
        content = format_subdomains_register(subdomains_status, as_json, pretty)
        output_result(content, output)


if __name__ == "__main__":
    cli()
