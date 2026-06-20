import re
import requests
import whois
import urllib
import urllib.request
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse

# 1. Check if URL has IP address instead of domain name
# Phishers use IP addresses to hide their identity
def havingIP(url):
    # This pattern matches any IP address like 192.168.1.1
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    if match:
        return 1  # phishing
    else:
        return 0  # legitimate

# 2. Check if URL has @ symbol
# Browser ignores everything before @ so phishers hide real URL after it
# Example: http://google.com@evil.com actually goes to evil.com
def haveAtSign(url):
    if "@" in url:
        return 1  # phishing
    else:
        return 0  # legitimate

# 3. Check length of URL
# Phishers use very long URLs to hide suspicious parts
def getLength(url):
    if len(url) < 54:
        return 0  # legitimate
    else:
        return 1  # phishing

# 4. Check depth of URL (how many subpages)
# Counts number of / in URL path
# Example: google.com/search/results/page has depth 3
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth += 1
    return depth  # returns actual number, not 0 or 1

# 5. Check for redirection // in URL
# If // appears anywhere after position 7, URL is redirecting somewhere else
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1  # phishing
        else:
            return 0  # legitimate
    else:
        return 0  # legitimate

# 6. Check if http/https appears in domain name
# Real sites don't put https in their domain name, phishers do to trick users
# Example: https-google-com.evil.com
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1  # phishing
    else:
        return 0  # legitimate

# 7. Check if URL uses shortening services like bit.ly
# Phishers use these to hide the real suspicious URL
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|" \
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|" \
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|" \
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"

def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1  # phishing
    else:
        return 0  # legitimate

# 8. Check for - in domain name
# Legitimate domains rarely use dash. Phishers use it like: google-login.com
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate

# 9, 10, 11, 12 — Domain based features
# These check WHOIS database for domain information
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if expiration_date is None or creation_date is None:
        return 1
    elif type(expiration_date) is list or type(creation_date) is list:
        return 1
    else:
        # If domain is less than 6 months old, likely phishing
        ageofdomain = abs((expiration_date - creation_date).days)
        if (ageofdomain / 30) < 6:
            return 1  # phishing
        else:
            return 0  # legitimate

def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list:
        return 1
    else:
        today = datetime.now()
        # If domain expires in less than 6 months, likely phishing
        end = abs((expiration_date - today).days)
        if (end / 30) < 6:
            return 0
        else:
            return 1

# 13. Check for invisible iFrame
# Phishers embed hidden iFrames to load malicious content
def iframe(response):
    if response == "":
        return 1  # phishing
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0  # legitimate
        else:
            return 1  # phishing

# 14. Check if link is hidden using onMouseOver
# Phishers show fake URL in status bar when you hover over a link
def mouseOver(response):
    if response == "":
        return 1  # phishing
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1  # phishing
        else:
            return 0  # legitimate

# 15. Check if right click is disabled
# Phishers disable right click so you can't inspect their page
def rightClick(response):
    if response == "":
        return 1  # phishing
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0  # legitimate
        else:
            return 1  # phishing

# 16. Check how many times page redirects
# Legitimate sites redirect once max. Phishing sites redirect 4+ times
def forwarding(response):
    if response == "":
        return 1  # phishing
    else:
        if len(response.history) <= 2:
            return 0  # legitimate
        else:
            return 1  # phishing

# MAIN FUNCTION — calls all 16 functions and returns a list of features
def featureExtraction(url):
    features = []

    # Address bar based features (8)
    features.append(havingIP(url))       # feature 1
    features.append(haveAtSign(url))     # feature 2
    features.append(getLength(url))      # feature 3
    features.append(getDepth(url))       # feature 4
    features.append(redirection(url))    # feature 5
    features.append(httpDomain(url))     # feature 6
    features.append(tinyURL(url))        # feature 7
    features.append(prefixSuffix(url))   # feature 8

    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns)                                            # feature 9
    features.append(1 if dns == 1 else domainAge(domain_name))     # feature 11
    features.append(1 if dns == 1 else domainEnd(domain_name))     # feature 12

    # HTML & JavaScript based features (4)
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))      # feature 13
    features.append(mouseOver(response))   # feature 14
    features.append(rightClick(response))  # feature 15
    features.append(forwarding(response))  # feature 16

    return features