import aiohttp
from typing import Dict
from nina.lib.colors import *
from nina.lib.core import Core, NoKey


class SearchDehashed:
    def __init__(self, domain, DATA_DIR, store, report_path):
        self.domain = domain
        self.DATA_DIR = DATA_DIR
        self.store = store
        self.report_path = report_path
        self.username, self.key = Core.dehashed_key()
        if self.key is None:
            raise NoKey("DeHashed")
        self.auth = aiohttp.BasicAuth(self.username, self.key, encoding='utf-8')
        self.db = "api.dehashed.com"
        self.results: Dict = dict()
        self.headers = {
            "Accept": "application/json",
            "User-Agent": Core.user_agent_list(),
        }
        self.size = 10000

    def write_report(self) -> None:
        f = open(self.report_path, "a")
        f.write(f"\n\n## Leaks found on DeHashed\n\n")
        for e in self.results:
            f.write(f"- Email: {e['email']}\n")
            f.write(f"- Username: {e['username']}\n")
            f.write(f"- Password: {e['password']}\n")
            f.write(f"- Hashed Password: {e['hashed_password']}\n")
            f.write(f"- Database: {e['database_name']}\n\n\n")
        f.close()

    async def search(self) -> None:
        running_message(f"Searching emails and links on DeHashed...")

        try:
            search_url = f'https://{self.db}/search?query=email:{self.domain}&size={self.size}'

            async with aiohttp.ClientSession(headers=self.headers, auth=self.auth) as sess:
                async with sess.get(search_url) as resp:
                    data = await resp.json()
                    balance = data['balance']

            warning_message(f"You have {balance} requests remaining in your API balance!")

            self.results = data['entries']

            if self.results is not None:
                for e in self.results:
                    print(f"- Email: {e['email']}")
                    print(f"- Username: {e['username']}")
                    print(f"- Password: {e['password']}")
                    print(f"- Hashed Password: {e['hashed_password']}")
                    print(f"- Database: {e['database_name']}")
                    print("\n")

                if self.store:
                    self.write_report()

        except Exception as e:
            error_message(f"An exception has occurred in DeHashed: {e}")


