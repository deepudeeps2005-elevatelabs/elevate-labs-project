# scanner/crawler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque


class SimpleCrawler:
    def __init__(self, max_pages=20, timeout=10):
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()

    def is_same_domain(self, base, target):
        return urlparse(base).netloc == urlparse(target).netloc

    def crawl(self, start_url):
        visited = set()
        queue = deque([start_url])
        pages = []

        while queue and len(pages) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue

            try:
                response = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue

            visited.add(url)
            pages.append((url, response.text))

            soup = BeautifulSoup(response.text, "html.parser")

            # Find links
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link["href"])
                if href.startswith("http") and self.is_same_domain(start_url, href):
                    if href not in visited:
                        queue.append(href)

        return pages
