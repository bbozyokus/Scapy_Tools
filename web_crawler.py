#!/usr/bin/env python
import requests,re, urllib.parse as urlparse,optparse

target_url = ""
target_links= []

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-u","--url",dest="target_url",help="--url http://example.com/")

    (options,arguments) = parser.parse_args()

    if not options.target_url:
        parser.error("[-] Please enter an url")
    return options

def extract_links_from(url):
    response = requests.get(url)
    return re.findall('(?:href=")(.*?)"',response.content.decode(errors="ignore"))

def crawl(url):
    href_links = extract_links_from(url)
    for link in href_links:
        link = urlparse.urljoin(url,link)

        if "#" in link:
            link = link.split("#")[0]

        if target_url in link and link not in target_links:
            target_links.append(link)
        print(link)

try:
    options=get_args()
    url=options.target_url
    crawl(url)
    
except KeyboardInterrupt:
    print("\n [-] Quitting...\n")
