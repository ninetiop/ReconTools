# Recon Toolkit CLI

## Presentation

Recon Toolkit CLI is a lightweight command-line tool designed to automate the first phases of reconnaissance during security assessments.

It focuses on DNS enumeration, subdomain discovery, and HTTP probing to quickly map the attack surface of a target domain.

## Features
- DNS record enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR)
- Subdomain enumeration via third-party sources
- HTTP probing of discovered subdomains
- Status code detection
- Basic technology fingerprinting
- Support for custom DNS resolvers
- Export results in JSON or CSV formats
- Human-readable (pretty) output for quick analysis

## Installation

The recommended way to install and run the project is using uv.

* install `uv` package

```bash
pip install uv
```

* create your virtual environment

```bash
uv venv && source .venv/bin/activate
```

* Synchronize with project's dependencies

```bash
uv sync
```

## Usage

### General help

```bash
./recon --doc
```

###  Usage

#### Subdomain enumeration

```bash
python recon.py enum_subdomains example.com
```

#### DNS record enumeration

```bash
python recon.py enum_records example.com -p
```

### Output formats

The tool supports multiple output formats:

- CSV text (default)
- Pretty-printed console output (-p)
- JSON (--json)
- File export (-o)