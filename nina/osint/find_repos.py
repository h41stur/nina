import aiohttp
import asyncio
from typing import List
from nina.lib.colors import *
from nina.lib.core import Core

class FindRepos:
    def __init__(self, domain, store, report_path, subs):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.git_repo: List[str] = list()
        self.git: List[str] = list()
        self.bit: List[str] = list()
        self.gitlab: List[str] = list()

    async def find_repos(self) -> None:
        running_message("Looking for public repositories...\n")
        asyncio.sleep(0.2)

        headers = {
            "User-Agent": Core.user_agent_list()
        }

        if self.domain not in self.subs:
            self.subs.append(self.domain)

        for i in self.subs:
            try:
                URL = f"https://{i}/.git"
                headers["Host"] = i
                async with aiohttp.ClientSession(headers=headers) as sess:
                    async with sess.get(URL) as resp:
                        status = str(resp.status)
                if f"{URL},{status}" not in self.git_repo:
                    self.git_repo.append(f"{URL},{status}")
                print(f"[{GREEN}+{RESET}] Git directory in {URL} responds with {status} status code.")
            except:
                pass

        try:
            URL = f"https://bitbucket.org/{self.domain.split('.')[0]}"
            headers["Host"] = "bitbucket.org"
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(URL) as resp:
                    status = str(resp.status)
            self.bit.append(f"{URL},{status}")
            print(f"[{GREEN}+{RESET}] Bitbucket repository in {URL} responds with {status} status code.")
        except:
            pass

        try:
            URL = f"https://github.com/{self.domain.split('.')[0]}"
            headers["Host"] = "github.com"
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(URL) as resp:
                    status = str(resp.status)
            if status == "200":
                self.git.append(f"{URL},{status}")
                print(f"[{GREEN}+{RESET}] Github repository in {URL} responds with {status} status code.")
        except:
            pass

        try:
            URL = f"https://gitlab.com/{self.domain.split('.')[0]}"
            headers["Host"] = "gitlab.com"
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(URL) as resp:
                    status = str(resp.status)
            if status == "200":
                self.gitlab.append(f"{URL},{status}")
                print(f"[{GREEN}+{RESET}] Gitlab repository in {URL} responds with {status} status code.")
        except:
            pass

        if self.git_repo or self.bit or self.git or self.gitlab:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Public repositories from {self.domain}\n\n")

                if self.git_repo:
                    f.write("### Git repositories:\n\n")
                    f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                    for i in self.git_repo:
                        f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                    f.write("\n\n")

                if self.git:
                    f.write("### GitHub repositories:\n\n")
                    f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                    for i in self.git:
                        f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                    f.write("\n\n")

                if self.bit:
                    f.write("### Bitbucket repositories:\n\n")
                    f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                    for i in self.bit:
                        f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                    f.write("\n\n")

                if self.gitlab:
                    f.write("### GitLab repositories:\n\n")
                    f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                    for i in self.gitlab:
                        f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                    f.write("\n\n")

                f.close()

