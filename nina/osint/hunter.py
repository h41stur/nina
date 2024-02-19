import aiohttp
import asyncio
from typing import List
from nina.lib.colors import *
from nina.lib.core import Core, NoKey

class SearchHunter:
    def __init__(self, domain, limit, DATA_DIR, store, report_path):
        self.domain = domain
        self.limit = 10 if limit > 10 else limit
        self.DATA_DIR = DATA_DIR
        self.store = store
        self.report_path = report_path
        self.results: List[str] = list()
        self.key = Core.hunter_key()
        self.emails: List = []
        if self.key is None:
            raise NoKey("Hunter")
        self.db = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={self.key}&limit={self.limit}"

    @staticmethod
    async def account_info(key: str) -> dict:
        headers = {"User-Agent": Core.user_agent_list()}
        info_url = f"https://api.hunter.io/v2/account?api_key={key}"
        async with aiohttp.ClientSession(headers=headers) as sess:
            async with sess.get(info_url) as resp:
                return await resp.json()

    def write_report(self) -> None:
        f = open(self.report_path, "a")
        f.write(f"\n\n## Emails found on hunter.io\n\n")
        for email in self.emails:
            f.write(f"- {email}\n")
        f.close()

    async def search(self) -> None:
        running_message(f"Searching for emails on hunter.io...")
        # get account info
        free = True
        acc_info = await self.account_info(self.key)
        if "plan_name" in acc_info['data'].keys()\
                and acc_info['data']['plan_name'].lower() == "free":
            free = True
        else:
            free = False

        # total number of requests available
        req_avail = (acc_info['data']['requests']['searches']['available']
                     - acc_info['data']['requests']['searches']['used'])
        headers = {"User-Agent": Core.user_agent_list()}
        if free:
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(self.db) as resp:
                    data = await resp.json()
            self.emails = list(sorted({email["value"] for email in data['data']['emails']}))
        else:
            # getting emails total available
            email_avail_url = f"https://api.hunter.io/v2/email-count?domain={self.domain}"
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(email_avail_url) as resp:
                    data = await resp.json()
            req_needed = data['data']['total'] // 100
            if req_avail < req_needed:
                warning_message(f"This account does not have enough requests to gather all emails")
                warning_message(f"Total requests available: {req_avail}, total requests needed to be made:"
                f"{req_needed}")
                return
            self.limit = 100
            for offset in range(0,  100 * req_needed, 100):
                req_url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={self.key}&limit{self.limit}&offset={offset}"
                async with aiohttp.ClientSession(headers=headers) as sess:
                    async with sess.get(req_url) as resp:
                        data = await resp.json()
                self.emails = list(sorted({email["value"] for email in data['data']['emails']}))
                await asyncio.sleep(1)

        if self.emails:
            for email in self.emails:
                print(f"- {email}")
            if self.store:
                self.write_report()


