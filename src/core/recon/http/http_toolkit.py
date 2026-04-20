import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)


HTTP_STATUS_CODES = {
    200: "200 OK",
    301: "301 Moved Permanently",
    302: "302 Found",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable",
    504: "504 Gateway Timeout",
}


class HTTPToolkit:
    async def _fetch(self, session, fqdn: str) -> tuple[str, dict]:
        results = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/116.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        for scheme in ("http://", "https://"):
            full_url = f"{scheme}{fqdn}"

            try:
                async with session.get(
                    full_url, timeout=5, ssl=False, headers=headers
                ) as response:
                    headers = response.headers
                    return {
                        "fqdn": fqdn,
                        "web-server": headers.get("server"),
                        "web-waf": "cloudflare" if headers.get("cf-ray") else None,
                        "waf-cf-ray": headers.get("cf-ray"),
                        "http_status": HTTP_STATUS_CODES.get(
                            response.status, f"{response.status} Unknown"
                        ),
                        "https_status": HTTP_STATUS_CODES.get(
                            response.status, f"{response.status} Unknown"
                        ),
                    }
            except Exception:
                results[scheme[:-3]] = None

    async def probe(self, fqdns: list[str]) -> dict:
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch(session, fqdn) for fqdn in fqdns]
            for coro in asyncio.as_completed(tasks):
                try:
                    res = await coro
                    if res is None:
                        continue
                    logger.info(f"[+] Probed {res['fqdn']}")
                    yield res
                except Exception as e:
                    logger.error(f"[!] Error probing URL: {e}")
