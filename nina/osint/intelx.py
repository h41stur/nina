import asyncio
import requests
import ujson
import aiohttp
from typing import Any, Set, List, Dict, Union
from nina.lib.colors import *
from nina.lib.core import Core, NoKey

class SearchIntelx:
    def __init__(self, domain, DATA_DIR, store, report_path):
        self.domain = domain
        self.DATA_DIR = DATA_DIR
        self.store = store
        self.report_path = report_path
        self.key = Core.intelx_key()
        if self.key is None:
            raise NoKey("IntelX")
        self.db = "https://2.intelx.io"
        self.phonebook: List[str] = list()
        self.leaks: List[str] = list()
        self.emails: Set = set()
        self.hosts: Set = set()
        self.info: tuple[Any, ...] = ()
        self.limit: int = 10000
        self.offset = -1
        self.headers: Dict = {
                "x-key": self.key,
                "User-Agent": f"{Core.user_agent_list()}-Nina",
            }
        self.data: Dict = {
                "term": self.domain,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": self.limit,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 2,
                "media": 0,
                "terminate": [],
                "target": 0,
            }

    async def parse_intelx(self, results: dict) -> tuple:
        if results is not None:
            for dic in results["selectors"]:
                f = dic["selectorvalue"]
                if "@" in f:
                    self.emails.add(f)
                else:
                    f = str(f)
                    if "http" in f or "https" in f:
                        if f[:5] == "https":
                            f = f[8:]
                        else:
                            f = f[7:]
                    self.hosts.add(f.replace(")", "").replace(",", ""))
            return self.emails, self.hosts
        return None, None

    async def search_phonebook(self) -> Union[list, None]:
        phonebook: List[str] = list()
        try:
            phonebook_resp = requests.post(
                f"{self.db}/phonebook/search", headers=self.headers, json=self.data
            )
            phonebook_id = ujson.loads(phonebook_resp.text)['id']

            await asyncio.sleep(5)

            search_url = f"{self.db}/phonebook/search/result?id={phonebook_id}&limit={self.limit}&offset={self.offset}"
            async with aiohttp.ClientSession(headers=self.headers) as sess:
                async with sess.get(search_url) as resp:
                    data = await resp.json()

            self.info = await self.parse_intelx(data)
        except Exception as e:
            error_message(f"An exception has occurred in IntelX: {e}")

        if self.info:
            self.emails = self.info[0]
            self.hosts = self.info[1]

        if self.emails:
            for e in self.emails:
                if e not in phonebook:
                    print(f"- {e}")
                    phonebook.append(e)
        if self.hosts:
            for h in self.hosts:
                if h not in phonebook:
                    print(f"- {h}")
                    phonebook.append(h)

        if phonebook:
            return phonebook
        else:
            return None

    async def search_leaks(self) -> Union[list, None]:
        # decreasing limit for better response
        limit = 10
        leaks: List[str] = list()
        try:
            intelligent_resp = requests.post(
                f"{self.db}/intelligent/search", headers=self.headers, json=self.data
            )
            intelligent_id = ujson.loads(intelligent_resp.text)['id']

            await asyncio.sleep(5)

            storage_url = f"{self.db}/intelligent/search/result?id={intelligent_id}&limit={limit}"

            async with aiohttp.ClientSession(headers=self.headers) as sess:
                async with sess.get(storage_url) as resp:
                    data = await resp.json()
            for i in data['records']:
                storageid = i['storageid']
                bucket = i['bucket']
                leak_url = f"{self.db}/file/view?f=2&storageid={storageid}&bucket={bucket}"
                async with aiohttp.ClientSession(headers=self.headers) as leak:
                    async with leak.get(leak_url) as leak_resp:
                        leak_data = await leak_resp.text()
                        leak_data = leak_data.split('\n')
                        for l in leak_data:
                            if self.domain in l and l not in leaks:
                                print(f"- {l}")
                                leaks.append(l)
        except Exception as e:
            error_message(f"An exception has occurred in IntelX: {e}")

        if leaks:
            return leaks
        else:
            return None

    def write_report(self) -> None:
        f = open(self.report_path, "a")
        f.write(f"\n\n## Informations found on intelx.io\n\n")
        if self.phonebook:
            f.write(f"\n\n### Emails and links\n\n")
            for p in self.phonebook:
                f.write(f"- {p}\n")

        if self.leaks:
            f.write(f"\n\n### Leaks\n\n")
            for l in self.leaks:
                f.write(f"- {l}\n")
        f.close()

    async def search(self) -> None:
        running_message(f"Searching emails and links on intelx.io...")
        self.phonebook = await self.search_phonebook()
        running_message(f"Searching leaks on intelx.io...")
        self.leaks = await self.search_leaks()

        if self.phonebook or self.leaks:
            if self.store:
                self.write_report()
        else:
            warning_message("No data found on IntelX!")



