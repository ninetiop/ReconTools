import aiohttp
import asyncio
import logging

from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class Crawler:
    def extract_links(self, html: str, base_url: str) -> dict:
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        for tag, attr in [("a", "href"), ("form", "action"), ("script", "src")]:
            for el in soup.find_all(tag, **{attr: True}):
                url = el.get(attr)

                if not url:
                    continue

                url = urljoin(base_url, url)
                links.add(url)

        return {"url": base_url, "links": links}

    async def _crawl_one(self, session, url: str):
        try:
            async with session.get(url, ssl=False, timeout=5) as response:
                html = await response.text()

                res = self.extract_links(html, base_url=url)

                logger.info(f"[+] Crawled {url} → {len(res['links'])} links")

                return res

        except Exception as e:
            logger.info(f"[-] Error crawling {url}: {e}")
            return None

    async def crawl(self, urls: list[str]):
        async with aiohttp.ClientSession() as session:
            tasks = [self._crawl_one(session, url) for url in urls]

            for coro in asyncio.as_completed(tasks):
                res = await coro
                if res:
                    yield res
