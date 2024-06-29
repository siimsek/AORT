#!/usr/bin/env python3
import sys

# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

try:
    import argparse
    import requests
    import re
    import socket
    import json
    import platform
    import dns.zone
    import warnings
    import dns.resolver
    import pydig
    from time import sleep
    import os
    import urllib3
    import dns.query
    import dns.exception
    import pkg_resources
    from Wappalyzer import Wappalyzer, WebPage
    import whois

except Exception as e:
    print(e)
    print(c.YELLOW + "\n[" + c.RED + "-" + c.YELLOW + "] ERROR requirements missing try to install the requirements: pip3 install -r requirements.txt" + c.END)
    sys.exit(0)

# Banner Function
def banner():
    print(c.RED + "\nAORT" + c.GREEN + " - " + c.RED + "All in One Recon Tool\n" + c.END)
    internet_check = socket.gethostbyname(socket.gethostname())
    if internet_check == "127.0.0.1":
        print(c.BLUE + "Internet connection: " + c.RED + "✕" + c.END)
    else:
        print(c.BLUE + "Internet connection: " + c.GREEN + "✔" + c.END)
    print(c.BLUE + "Target: " + c.GREEN + domain + c.END)

# Argument parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="AORT - All in One Recon Tool")
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument('-t', '--token', help="api token of hunter.io to discover mail accounts and employees", required=False)
    p.add_argument("-p", "--portscan", help="perform a fast and stealthy scan of the most common ports", action='store_true', required=False)
    p.add_argument("-a", "--axfr", help="try a domain zone transfer attack", action='store_true', required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true', required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-s", "--subtakeover", help="check if any of the subdomains are vulnerable to Subdomain Takeover", action='store_true', required=False)
    p.add_argument("-r", "--repos", help="try to discover valid repositories and s3 servers of the domain", action='store_true', required=False)
    p.add_argument("-c", "--check", help="check active subdomains and store them into a file", action='store_true', required=False)
    p.add_argument("--secrets", help="crawl the web page to find secrets and api keys", action='store_true', required=False)
    p.add_argument("--enum", help="stealthily enumerate and identify common technologies", action='store_true', required=False)
    p.add_argument("--whois", help="perform a whois query to the domain", action='store_true', required=False)
    p.add_argument("--wayback", help="find useful information about the domain using The Wayback Machine and other services", action="store_true", required=False)
    p.add_argument("--all", help="perform all the enumeration at once (best choice)", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)
    return p.parse_args()

utils_dir = pkg_resources.resource_filename('aort', 'utils')

def create_output_dir(domain_name):
    output_dir = os.path.expanduser(f"~/aort-output/{domain_name}")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    return output_dir

# Nameservers Function 
def ns_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    try:
        data = dns.resolver.resolve(domain, 'NS')
        for ns in data:
            print(c.YELLOW + str(ns) + c.END)
    except:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# IPs discover Function
def ip_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering IPs of the domain...\n" + c.END)
    sleep(0.2)
    try:
        data = dns.resolver.resolve(domain, 'A')
        for ip in data:
            print(c.YELLOW + ip.to_text() + c.END)
    except:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    try:
        data = dns.resolver.resolve(domain, 'TXT')
        for info in data:
            print(c.YELLOW + info.to_text() + c.END)
    except:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Function to discover the IPv6 of the target
def ipv6_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Getting ipv6 of the domain...\n" + c.END)
    sleep(0.2)
    try:
        data = pydig.query(domain, 'AAAA')
        for info in data:
            print(c.YELLOW + info + c.END)
    except:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    try:
        data = dns.resolver.resolve(domain, 'MX')
        for server in data:
            print(c.YELLOW + str(server).split(" ")[1] + c.END)
    except:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Domain Zone Transfer Attack Function
def axfr(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting Domain Zone Transfer attack...\n" + c.END)
    sleep(0.2)
    try:
        ns_answer = dns.resolver.resolve(domain, 'NS')
        for server in ns_answer:
            ip_answer = dns.resolver.resolve(server.target, 'A')
            for ip in ip_answer:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                    for host in zone:
                        print(c.YELLOW + "Found Host: {}".format(host) + c.END)
                except Exception as e:
                    print(c.YELLOW + "NS {} refused zone transfer!".format(server) + c.END)
                    continue
    except dns.resolver.NoAnswer:
        print("No NS records found for the domain.")
    except dns.resolver.NXDOMAIN:
        print("The domain does not exist.")
    except dns.resolver.Timeout:
        print("DNS resolution timed out.")
    except Exception as e:
        print("An error occurred:", e)

# Use the token
def crawlMails(domain, api_token):
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Discovering valid mail accounts and employees..." + c.END)
    sleep(1)
    api_url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_token}"
    r = requests.get(api_url)
    response_data = r.json()
    domain_name = domain.split(".")[0]
    output_dir = create_output_dir(domain_name)
    mails_file = os.path.join(output_dir, f"{domain_name}-mails-data.txt")
    with open(mails_file, "w") as file:
        file.write(r.text)

    counter = 0
    for value in response_data["data"]["emails"]:
        if value["first_name"] and value["last_name"]:
            counter = 1
            print(c.YELLOW + value["first_name"] + " " + value["last_name"] + " - " + value["value"] + c.END)
        else:
            counter = 1
            print(c.YELLOW + value["value"] + c.END)
    if counter == 0:
        print(c.YELLOW + "\nNo mails or employees found" + c.END)
    else:
        print(c.YELLOW + "\nMore mail data stored in " + mails_file + c.END)


# Function to check subdomain takeover
def subTakeover(all_subdomains):
    vuln_counter = 0
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Checking if any subdomain is vulnerable to takeover\n" + c.END)
    sleep(1)
    for subdom in all_subdomains:
        try:
            sleep(0.05)
            resquery = dns.resolver.resolve(subdom, 'CNAME')
            for resdata in resquery:
                resdata = resdata.to_text()
                if subdom[-8:] in resdata:
                    r = requests.get("https://" + subdom, allow_redirects=False)
                    if r.status_code == 200:
                        vuln_counter += 1
                        print(c.YELLOW + subdom + " appears to be vulnerable" + c.END)
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
        except:
            pass
    if vuln_counter <= 0:
        print(c.YELLOW + "No subdomains are vulnerable" + c.END)

# Function to enumerate github and cloud
def cloudgitEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for git repositories and public development info\n" + c.END)
    sleep(0.2)
    domain_split = domain.split(".")[0]
    repos = [
        f"https://{domain}/.git/",
        f"https://bitbucket.org/{domain_split}",
        f"https://github.com/{domain_split}",
        f"https://gitlab.com/{domain_split}"
    ]
    for repo in repos:
        try:
            r = requests.get(repo, verify=False)
            print(c.YELLOW + f"Repository URL: {repo} - {r.status_code} status code" + c.END)
        except:
            pass

# Wayback Machine function
def wayback(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Using The Wayback Machine to discover endpoints" + c.END)
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = requests.get(wayback_url, timeout=20)
        results = r.json()[1:]
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        return

    domain_name = domain.split(".")[0]
    output_dir = create_output_dir(domain_name)
    wayback_file = os.path.join(output_dir, f"{domain_name}-wayback.txt")
    with open(wayback_file, "w") as file:
        for result in results:
            file.write(result[0] + "\n")

    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=20)
        myresp = r.json()
        results = myresp["results"]
        with open(wayback_file, "a") as file:
            for res in results:
                file.write(res["task"]["url"] + "\n")
    except:
        pass

    print(c.YELLOW + f"\nAll URLs stored in {wayback_file}" + c.END)
    sleep(0.3)
    filter_wayback_output(wayback_file, domain_name)

def filter_wayback_output(wayback_file, domain_name):
    output_dir = create_output_dir(domain_name)
    print(c.YELLOW + f"\nGetting .json endpoints from URLs..." + c.END)
    sleep(0.5)
    json_file = os.path.join(output_dir, f"{domain_name}-json.txt")
    with open(wayback_file, "r") as file:
        urls = file.readlines()
    json_endpoints = [url for url in urls if ".json" in url]
    with open(json_file, "w") as file:
        for json_url in json_endpoints:
            file.write(json_url)
    print(c.YELLOW + f"JSON endpoints stored in {json_file} ({len(json_endpoints)} endpoints)" + c.END)
    sleep(0.4)
    print(c.YELLOW + f"Filtering out URLs to find potential XSS and Open Redirect vulnerable endpoints..." + c.END)
    sleep(0.2)
    filter_redirects_and_xss(wayback_file, domain_name)

def filter_redirects_and_xss(wayback_file, domain_name):
    output_dir = create_output_dir(domain_name)
    wayback_content = open(wayback_file, "r").readlines()
    redirect_urls = []
    redirects_path = os.path.join(utils_dir, 'redirects.json')
    if not os.path.exists(redirects_path):
        download_file(redirects_path, "https://raw.githubusercontent.com/siimsek/AORT/main/utils/redirects.json")
    with open(redirects_path) as redirects_raw:
        redirects_json = json.load(redirects_raw)
    for line in wayback_content:
        for json_line in redirects_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "FUZZ"
                if endpoint_url not in redirect_urls:
                    redirect_urls.append(endpoint_url)
    redirect_file = os.path.join(output_dir, f"{domain_name}-redirects.txt")
    with open(redirect_file, "w") as file:
        for filtered_url in redirect_urls:
            file.write(filtered_url + "\n")
    print(c.YELLOW + f"Open Redirects endpoints stored in {redirect_file} ({len(redirect_urls)} endpoints)" + c.END)

    xss_urls = []
    xss_path = os.path.join(utils_dir, 'xss.json')
    if not os.path.exists(xss_path):
        download_file(xss_path, "https://raw.githubusercontent.com/siimsek/AORT/main/utils/xss.json")
    with open(xss_path) as xss_raw:
        xss_json = json.load(xss_raw)
    for line in wayback_content:
        for json_line in xss_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E"
                if endpoint_url not in xss_urls:
                    xss_urls.append(endpoint_url)
    xss_file = os.path.join(output_dir, f"{domain_name}-xss.txt")
    with open(xss_file, "w") as file:
        for filtered_url in xss_urls:
            file.write(filtered_url + "\n")
    print(c.YELLOW + f"XSS endpoints stored in {xss_file} ({len(xss_urls)} endpoints)" + c.END)
    sleep(0.1)

def download_file(local_path, url):
    r = requests.get(url)
    with open(local_path, "w") as file:
        file.write(r.text)

# Query the domain
def whoisLookup(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing Whois lookup..." + c.END)

    sleep(1.2)
    try:
        w = whois.whois(domain)  # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)
    try:
        print(c.YELLOW + f"\n{w}" + c.END)
    except:
        print(c.YELLOW + "\nAn error has ocurred or unable to whois " + domain + c.END)

# Function to thread when probing active subdomains
def checkStatus(subdomain, file):
    try:
        r = requests.get("https://" + subdomain, timeout=2)
        if r.status_code:
            file.write("https://" + subdomain + "\n")
    except:
        try:
            r = requests.get("http://" + subdomain, timeout=2)
            if r.status_code:
                file.write("http://" + subdomain + "\n")
        except:
            pass

# Check status function
def checkActiveSubs(domain, doms):
    global file
    import threading
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Probing active subdomains..." + c.END)
    if len(doms) >= 100:
        subs_total = len(doms)
        option = input(c.YELLOW + f"\nThere are a lot of subdomains to check, ({subs_total}) do you want to check all of them [y/n]: " + c.END)
        if option == "n" or option == "no":
            sleep(0.2)
            return
    domain_name = domain.split(".")[0]
    output_dir = create_output_dir(domain_name)
    active_subs_file = os.path.join(output_dir, f"{domain_name}-active-subs.txt")
    file = open(active_subs_file, "w")
    threads_list = []
    for subdomain in doms:
        t = threading.Thread(target=checkStatus, args=(subdomain, file))
        t.start()
        threads_list.append(t)
    for proc_thread in threads_list:
        proc_thread.join()
    print(c.YELLOW + f"\nActive subdomains stored in {active_subs_file}" + c.END)


# Check if common ports are open
def portScan(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Scanning most common ports on " + domain + "\n" + c.END)
    ports = [21, 22, 23, 25, 26, 43, 53, 69, 80, 81, 88, 110, 135, 389, 443, 445, 636, 873, 1433, 2049, 3000, 3001, 3306, 4000, 4040, 5000, 5001, 5985, 5986, 8000, 8001, 8080, 8081, 27017]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.40)
        result = sock.connect_ex((domain, port))
        if result == 0:
            print(c.YELLOW + "Port " + str(port) + " - OPEN" + c.END)
        sock.close()

# Look for secrets and API keys
def findSecrets(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to find possible secrets and API keys..." + c.END)
    for protocol in ["https", "http"]:
        findSecretsFromUrl(protocol + "://" + domain)

def findSecretsFromUrl(url):
    try:
        r = requests.get(url, verify=False)
    except:
        return
    js_list = []
    url_list = re.findall(r'src="(.*?)"', r.text) + re.findall(r'href="(.*?)"', r.text)
    for endpoint in url_list:
        if ".js" in endpoint and "https://" not in endpoint:
            js_list.append(endpoint)
    if js_list:
        print(c.YELLOW + "\nDiscovered JS endpoints:" + c.END)
    for js in js_list:
        print(c.YELLOW + url + js + c.END)
    key_counter = 0
    for js_endpoint in js_list:
        try:
            r = requests.get(url + js_endpoint, verify=False)
        except:
            continue
        if "https://maps.googleapis.com/" in r.text:
            maps_api_key = re.findall(r'src="https://maps.googleapis.com/(.*?)"', r.text)[0]
            print(c.YELLOW + "\nMaps API key found: " + maps_api_key + c.END)
            key_counter = 1
        try:
            google_api = re.findall(r'AIza[0-9A-Za-z-_]{35}', r.text)[0]
            if google_api:
                print(c.YELLOW + "\nGoogle API found: " + google_api + c.END)
                key_counter = 1
        except:
            pass
        try:
            google_oauth = re.findall(r'ya29\.[0-9A-Za-z\-_]+', r.text)[0]
            if google_oauth:
                print(c.YELLOW + "\nGoogle OAuth found: " + google_oauth + c.END)
                key_counter = 1
        except:
            pass
        try:
            amazon_aws_url = re.findall(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com', r.text)[0]
            if amazon_aws_url:
                print(c.YELLOW + "\nAmazon AWS URL found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass
        try:
            stripe_key = re.findall(r'"pk_live_.*"', r.text)[0].replace('"', '')
            if stripe_key:
                print(c.YELLOW + "\nStripe key found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass
    if key_counter != 1:
        print(c.YELLOW + "\nNo secrets found" + c.END)

# Perform basic enumeration
def basicEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing some basic enumeration...\n" + c.END)
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + domain)
        info = wappalyzer.analyze_with_versions(webpage)
        if info:
            print(c.YELLOW + json.dumps(info, sort_keys=True, indent=4) + c.END)
        else:
            print(c.YELLOW + "\nNo common technologies found" + c.END)
        endpoints = ["robots.txt", "xmlrpc.php", "wp-cron.php", "actuator/heapdump", "datahub/heapdump", "datahub/actuator/heapdump", "heapdump", "admin/", ".env", ".config", "version.txt", "README.md", "license.txt", "config.php.bak", "api/", "feed.xml", "CHANGELOG.md", "config.json", "cgi-bin/", "env.json", ".htaccess", "js/", "kibana/", "log.txt"]
        for end in endpoints:
            r = requests.get(f"https://{domain}/{end}", timeout=4)
            print(c.YELLOW + f"https://{domain}/{end} - {r.status_code}" + c.END)
    except:
        print(c.YELLOW + "An error has occurred or unable to enumerate" + c.END)

# Main Domain Discoverer Function
def SDom(domain, filename):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering subdomains using passive techniques...\n" + c.END)
    sleep(0.1)
    global doms
    doms = []
    crt_domains = get_crt_domains(domain)
    alienvault_domains = get_alienvault_domains(domain)
    hackertarget_domains = get_hackertarget_domains(domain)
    rapiddns_domains = get_rapiddns_domains(domain)
    riddler_domains = get_riddler_domains(domain)
    threatminer_domains = get_threatminer_domains(domain)
    urlscan_domains = get_urlscan_domains(domain)

    doms = list(set(crt_domains + alienvault_domains + hackertarget_domains + rapiddns_domains + riddler_domains + threatminer_domains + urlscan_domains))

    domain_name = domain.split(".")[0]
    output_dir = create_output_dir(domain_name)
    if filename:
        filename = os.path.join(output_dir, filename)
        with open(filename, "w") as f:
            for dom in doms:
                f.write(dom + "\n")

    if doms:
        print(c.YELLOW + "+" + "-"*47 + "+")
        for value in doms:
            print(f"| {value}" + " " * (46 - len(value)) + "|")
        print("+" + "-"*47 + "+" + c.END)
        print(c.YELLOW + "\nTotal discovered subdomains: " + str(len(doms)) + c.END)
        if filename:
            print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Output stored in " + filename)
    else:
        print(c.YELLOW + "No subdomains discovered through SSL transparency" + c.END)

def get_crt_domains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=20)
        formatted_json = json.dumps(r.json(), indent=4)
        return sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
    except:
        return []

def get_alienvault_domains(domain):
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        return sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
    except:
        return []

def get_hackertarget_domains(domain):
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        return re.findall(r'(.*?),', r.text)
    except:
        return []

def get_rapiddns_domains(domain):
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        return re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
    except:
        return []

def get_riddler_domains(domain):
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        return re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
    except:
        return []

def get_threatminer_domains(domain):
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = r.json()
        return raw_domains['results']
    except:
        return []

def get_urlscan_domains(domain):
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        return sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
    except:
        return []

# Check if the given target is active
def checkDomain(domain):
    try:
        socket.gethostbyname(domain)
    except:
        print(c.YELLOW + "\nTarget doesn't exist or is down" + c.END)
        sys.exit(1)

# Program workflow starts here
def main():
    program_version = 2.0
    urllib3.disable_warnings()
    warnings.simplefilter('ignore')

    if "--version" in sys.argv:
        print("\nAll in One Recon Tool v" + str(program_version) + " - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # Check domain format
    if "." not in parse.domain:
        print(c.YELLOW + "\nInvalid domain format, example: domain.com" + c.END)
        sys.exit(0)

    if parse.output:
        filename = parse.output
    else:
        filename = None

    global domain
    domain = parse.domain
    checkDomain(domain)

    if parse.all:
        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            banner()
            SDom(domain, filename)
            portScan(domain)
            ns_enum(domain)
            axfr(domain)
            mail_enum(domain)
            ip_enum(domain)
            ipv6_enum(domain)
            txt_enum(domain)
            whoisLookup(domain)
            basicEnum(domain)
            findSecrets(domain)
            cloudgitEnum(domain)
            checkActiveSubs(domain, doms)
            wayback(domain)
            subTakeover(doms)

            if parse.token:
                crawlMails(domain, parse.token)
            else:
                print(c.BLUE + "\n[" + c.GREEN + "-" + c.BLUE + "] No API token provided, skipping email crawling" + c.END)
            try:
                file.close()
            except:
                pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

        sys.exit(0)

    if parse.domain:
        domain = parse.domain
        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            banner()
            SDom(domain, filename)
            if parse.portscan:
                portScan(domain)
            if parse.nameservers:
                ns_enum(domain)
            if parse.axfr:
                axfr(domain)
            if parse.mail:
                mail_enum(domain)
            if parse.ip:
                ip_enum(domain)
            if parse.ipv6:
                ipv6_enum(domain)
            if parse.extra:
                txt_enum(domain)
            if parse.whois:
                whoisLookup(domain)
            if parse.enum:
                basicEnum(domain)
            if parse.secrets:
                findSecrets(domain)
            if parse.repos:
                cloudgitEnum(domain)
            if parse.check:
                checkActiveSubs(domain, doms)
            if parse.wayback:
                wayback(domain)
            if parse.subtakeover:
                subTakeover(doms)
            if parse.token:
                crawlMails(domain, parse.token)
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

if __name__ == '__main__':
    main()
