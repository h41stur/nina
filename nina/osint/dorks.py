import tldextract
import requests
import urllib3
import warnings
from time import sleep
from googlesearch import search
from nina.lib.colors import *
from nina.lib.core import Core


urllib3.disable_warnings()
warnings.simplefilter("ignore")

class Dorks:
    def __init__(self, domain, store, report_path):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.links = {}
        self.target = tldextract.extract(str(domain)).domain

    def dorks(self) -> None:
        running_message("Dorking...")
        user_agent = Core.user_agent_list()
        terms = {
            ".git folders": f"inurl:\"/.git\" {self.domain} -github",
            "Backup files": f"site:{self.domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
            "Exposed documents": f"site:{self.domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
            "Confidential documents": f"inurl:{self.target} not for distribution | confidential | \"employee only\" | proprietary | top secret | classified | trade secret | internal | private filetype:xls OR filetype:csv OR filetype:doc OR filetype:pdf",
            "Config files": f"site:{self.domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini",
            "Database files": f"site:{self.domain} ext:sql | ext:dbf | ext:mdb",
            "Other files": f"site:{self.domain} intitle:index.of | ext:log | ext:php intitle:phpinfo \"published by the PHP Group\" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:\"/phpinfo.php\" | inurl:\".htaccess\" | ext:swf",
            "SQL errors": f"site:{self.domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\"",
            "PHP errors": f"site:{self.domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"",
            "Wordpress files": f"site:{self.domain} inurl:wp-content | inurl:wp-includes",
            "Project management sites": f"site:trello.com | site:*.atlassian.net \"{self.target}\"",
            "GitLab/GitHub/Bitbucket": f"site:github.com | site:gitlab.com | site:bitbucket.org \"{self.target}\"",
            "Cloud buckets S3/GCP": f"site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com \"{self.target}\"",
            "Traefik": f"intitle:traefik inurl:8080/dashboard \"{self.target}\"",
            "Jenkins": f"intitle:\"Dashboard [Jenkins]\" \"{self.target}\"",
            "Login pages": f"site:{self.domain} inurl:signup | inurl:register | intitle:Signup",
            "Open redirects": f"site:{self.domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http",
            "Code share sites": f"site:sharecode.io | site:controlc.com | site:codepad.co |site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net \"{self.target}\"",
            "Other 3rd parties sites": f"site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com \"{self.target}\"",
            "Stackoverflow": f"site:stackoverflow.com \"{self.domain}\"",
            "Pastebin-like sites": f"site:justpaste.it | site:heypasteit.com | site:pastebin.com \"{self.target}\"",
            "Apache Struts RCE": f"site:{self.domain} ext:action | ext:struts | ext:do",
            "Linkedin employees": f"site:linkedin.com employees {self.domain}",
        }

        r = requests.get('https://google.com', verify=False)

        for title, dork in terms.items():
            result = []
            try:
                for r in search(dork,
                                user_agent=user_agent,
                                tld="com", lang="en", num=10, start=0, stop=None, pause=2):
                    if r not in result:
                        result.append(r)
                sleep(10)
                if result:
                    print(f"\n[{BLUE}*{RESET}] {title}")
                    for i in result:
                        print(f"\t{GREEN}-{RESET} {i}")
                    self.links[title] = result
            except KeyboardInterrupt:
                warning_message("Interrupt handler received, exiting...\n")
            except Exception as e:
                if "429" in str(e):
                    warning_message("Too many requests, unable to obtain a response from Google.")
                    break
                pass

            sleep(10)

        if self.links:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Dork links\n\n")
                for l in self.links:
                    f.write(f"\n\n### {l}\n")
                    for i in self.links[l]:
                        f.write(f"\n- {i}")
                f.close()
        else:
            warning_message("No results.")
