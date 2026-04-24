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
    async def _fetch(self, session, fqdn: str):
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,*/*",
        }

        for scheme in ("https://", "http://"):
            url = f"{scheme}{fqdn}"

            try:
                async with session.get(
                    url, timeout=5, ssl=False, headers=headers
                ) as response:
                    return {
                        "fqdn": fqdn,
                        "scheme": scheme[:-3],
                        "status": response.status,
                        "http_status": HTTP_STATUS_CODES.get(response.status),
                        "server": response.headers.get("server"),
                        "cf_ray": response.headers.get("cf-ray"),
                        "waf": "cloudflare" if response.headers.get("cf-ray") else None,
                    }

            except Exception:
                continue

        return None

    async def probe(self, fqdns: list[str]) -> dict:
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch(session, fqdn) for fqdn in fqdns]
            for coro in asyncio.as_completed(tasks):
                try:
                    res = await coro
                    if res:
                        logger.info(
                            f"[+] Alive: {res['fqdn']} ({res['scheme']}) → HTTP {res['status']}"
                        )
                        yield res
                except Exception as e:
                    logger.info(f"[-] Error probing {res['fqdn']}: {e}")
                    pass
