import aiohttp
import asyncio
from urllib import parse
from typing import Union, Any, Dict, List, NamedTuple, Tuple
from nina.lib.colors import *
from nina.lib.core import Core, NoKey

class SearchError(NamedTuple):
    status_code: int
    body: Any

class SearchSuccess(NamedTuple):
    links: List[str]
    next: Union[int, None]
    last: Union[int, None]

class SearchRetry(NamedTuple):
    time: float

class SearchGithub:
    def __init__(self, corp, limit, DATA_DIR, store, report_path):
        self.corp = corp
        self.limit = limit
        self.DATA_DIR = DATA_DIR
        self.store = store
        self.report_path = report_path
        self.results: List[str] = list()
        self.server = "api.github.com"
        self.counter: int = 0
        self.page: Union[int, None] = 1
        self.key = Core.github_key()
        if self.key is None:
            raise NoKey("GitHub")

    async def git_search(self, page: int) -> Tuple[str, dict, int, Any]:
        if page is None:
            url = f'https://{self.server}/search/code?q="{self.corp}"'
        else:
            url = f'https://{self.server}/search/code?q="{self.corp}"&page={page}'
        headers = {
            "Host": self.server,
            "User-Agent": Core.user_agent_list(),
            "Accept": "application/vnd.github.v3.text-match+json",
            "Authorization": f"token {self.key}",
        }

        async with aiohttp.ClientSession(headers=headers) as sess:
            async with sess.get(url) as resp:
                return await resp.text(), await resp.json(), resp.status, resp.links

    @staticmethod
    def page_response(page: str, links) -> Union[int, None]:
        page_link = links.get(page)
        if page_link:
            parsed = parse.urlparse(str(page_link.get("url")))
            params = parse.parse_qs(parsed.query)
            pages: List[Any] = params.get("page", [None])
            page_number = pages[0] and int(pages[0])
            return page_number
        else:
            return None

    async def get_fragments_links(self, json_data: dict) -> List[str]:
        items: List[Dict[str, Any]] = json_data.get("items") or list()
        links_api: List[str] = list()
        links: List[str] = list()
        for item in items:
            matches = item.get("text_matches") or list()
            for match in matches:
                links_api.append(match.get("object_url"))
        for l in links_api:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(l) as resp:
                    j = await resp.json()
                    try:
                        _links = j.get("_links")
                        html = _links.get("html")
                        if html is not None and html not in links:
                            links.append(html)
                    except Exception as e:
                        pass
        return links

    async def git_response(
            self, response: Tuple[str, dict, int, Any]
    ) -> Union[SearchError, SearchRetry, SearchSuccess]:
        text, json_data, status, links = response
        if status == 200:
            results = await self.get_fragments_links(json_data)
            # results = self.fragments_resp(json_data)
            next = self.page_response("next", links)
            last = self.page_response("last", links)
            return SearchSuccess(results, next, last)
        elif status == 429 or status == 403:
            return SearchRetry(60)
        else:
            try:
                return SearchError(status, json_data)
            except ValueError:
                return SearchError(status, text)

    @staticmethod
    def next_or_end(result: SearchSuccess) -> Union[int, None]:
        if result.next is not None:
            return result.next
        else:
            return result.last

    def write_report(self) -> None:
        f = open(self.report_path, "a")
        f.write(f"\n\n## GitHub code fragments with {self.corp} mentions\n\n")
        for link in self.results:
            f.write(f"- {link}\n")
        f.close()

    async def search(self) -> None:
        running_message(f"Searching for GitHub code mentions...")
        try:
            while self.counter <= self.limit and self.page is not None:
                response = await self.git_search(self.page)
                result = await self.git_response(response)
                if isinstance(result, SearchSuccess):
                    for link in result.links:
                        self.results.append(link)
                        self.counter = self.counter + 1
                    self.page = self.next_or_end(result)
                    await asyncio.sleep(Core.delay())
                elif isinstance(result, SearchRetry):
                    sleepy = Core.delay() + result.time
                    warning_message(f"Retrying page in {sleepy} seconds...")
                    await asyncio.sleep(sleepy)
                elif isinstance(result, SearchError):
                    raise Exception(
                        f"\tException occurred: status_code: {result.status_code} reason: {result.body}"
                    )
                else:
                    raise Exception("\tUnknown exception occurred")
        except Exception as e:
            error_message(f"An exception has occurred: {e}")

        if self.results:
            for link in self.results:
                print(f"- {link}")
            if self.store:
                self.write_report()
        else:
            warning_message("No GitHub code mentions found! (maybe IP rate-limit was reached)")


