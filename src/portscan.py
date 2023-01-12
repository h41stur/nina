import requests
import sys
import ast
from prettytable import PrettyTable
from time import sleep
from bs4 import BeautifulSoup as bs
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] Nina needs python 3.4 > ro run!")
    sys.exit()

# portscan request function
def portscan_request(s):

    hackertarget = 'https://hackertarget.com/nmap-online-port-scanner/'
    header = \
        {"User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36'}

    result = {}
    partial = {}
    ports = []

    name_of_nonce_field = ""

    # getting name_of_nonce_field value
    try:
        r = requests.get(hackertarget, verify=False)
    except Exception as e:
        return None

    soup = bs(r.text, 'html.parser')
    inputs = soup.find_all('input')
    for i in inputs:
        if not name_of_nonce_field:
            try:
                if i.attrs["name"] == "name_of_nonce_field":
                    name_of_nonce_field = i.attrs["value"]
            except Exception as e:
                pass

    if name_of_nonce_field:
        body = {"theinput": s, "thetest": "nmap", "name_of_nonce_field": name_of_nonce_field,
                "_wp_http_referer": "%2Fnmap-online-port-scanner%2F"}

        try:
            r = requests.post(hackertarget, headers=header, data=body)
        except Exception as e:
            return None
        soup = bs(r.text, 'html.parser')
        scan = soup.find_all('pre')
        for value in scan:
            try:
                if value.attrs["id"] == "formResponse":
                    line = value.text
                    line = line.split("\n")
                    for atr in line:
                        if atr[:1].isdigit():
                            atr = " ".join(atr.split())
                            atr = atr.split(" ")
                            atr[0] = atr[0].replace("/tcp", "")
                            partial["port"] = atr[0]
                            partial["status"] = atr[1]
                            partial["service"] = atr[2]
                            if partial not in ports:
                                ports.append(str(partial))
            except Exception as e:
                pass

        if ports:
            result["host"] = s
            result["result"] = ports
            return result
        else:
            return None

# portscan function
def portscan(domain, store, dirFile, subs, THREADS):

    print(f"\n{BLUE}[*] Portscanning...\n")
    sleep(0.2)

    if domain not in subs:
        subs.append(domain)

    results = []

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(portscan_request, s) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None and resp not in results:
            results.append(resp)

    if results:
        if store:
            f = open(dirFile + "/" + domain + ".report.md", "a")
            f.write(f"\n\n## Portscan Results\n\n")
            f.close()
        for i in results:
            if i:
                print(f"[{GREEN}+{RESET}] {i['host']}\n")
                table = PrettyTable(["Port", "Status", "Service (possible)"])
                for r in i["result"]:
                    r = ast.literal_eval(r)
                    table.add_row([r['port'], r['status'], r['service']])
                print(table)
                print("\n")

                if store:
                    f = open(dirFile + "/" + domain + ".report.md", "a")
                    f.write(f"\n\n### Host {i['host']}\n")
                    f.write("|" + " PORT \t\t\t\t| STATUS \t\t\t| SERVICE (Possible)|\n")
                    f.write("|" + "-"*23 + "|" + "-"*23 + "|" + "-"*23 + "|\n")
                    for r in i["result"]:
                        r = ast.literal_eval(r)
                        f.write(f"|{r['port']}\t\t\t\t|{r['status']}\t\t\t\t|{r['service']}\t\t\t\t|\n")
                    f.close()
    else:
        print(f"[{YELLOW}!{RESET}] Unable to execute portscan, maybe hackertarget.com API count exceeded!")