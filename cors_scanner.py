#!/usr/bin/env python3


__author__ = "Jake Miller (@LaconicWolf)"
__date__ = "20191119"
__version__ = "0.01"
__description__ = """A multi-threaded scanner to help discover CORS flaws."""


import sys

if not sys.version.startswith('3'):
    print('\n[-] This script will only work with Python3. Sorry!\n')
    exit()

import os
import threading
import time
import random
import argparse
from queue import Queue
from urllib.parse import urlparse
from random import randrange, choice
from string import ascii_lowercase

# Third party modules
missing_modules = []
try:
    import requests
    import tqdm
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    missing_modules.append(missing_module)

if missing_modules:
    for m in missing_modules:
        print('[-] Missing module: {}'.format(m))
        print('[*] Try running "pip3 install {}", or do an Internet search for installation instructions.\n'.format(m.strip("'")))
    exit()
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def get_random_useragent():
    """Returns a randomly chosen User-Agent string."""
    win_edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
    win_firefox = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0'
    win_chrome = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"
    lin_firefox = 'Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0'
    mac_chrome = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36'
    ie = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)'
    ua_dict = {
        1: win_edge,
        2: win_firefox,
        3: win_chrome,
        4: lin_firefox,
        5: mac_chrome,
        6: ie
    }
    rand_num = randrange(1, (len(ua_dict) + 1))
    return ua_dict[rand_num]


def print_dict(origin, d):
    """Prints the contents of a dictionary."""
    print(f'Origin: {origin}')
    for k in d:
        with print_lock:
            print(f"{k.upper()}:{d.get(k)}")


def parse_cors_dict(d):
    """Formats dictionary values as a list for printing."""
    cors_headers = [
        'acao',
        'acac',
        'acam',
        'acah',
        'acma',
        'aceh'
    ]
    parsed_list = []
    for header in cors_headers:
        if header in d.keys():
            parsed_list.append(d.get(header))
        else:
            parsed_list.append('')
    return parsed_list


def write_csv(data):
    """Writes a CSV file. Appends to file if it already exists."""
    col_headers = [
        'URL',
        'Origin',
        'ACAO',
        'ACAC',
        'ACAM',
        'ACAH',
        'ACMA',
        'ACEH'
    ]
    csv_name = args.csv_name if args.csv_name else 'CORS_Results-' + time.strftime('%d%b%Y%H%M%S') + '.csv'
    if os.path.exists(csv_name):
        print()
        print(f'[+] Appending to {csv_name}.')
        with open(csv_name, 'a') as fh:
            for item in data:
                url = item[0]
                origin = item[1]
                cors_dict = item[2]
                parsed_list = parse_cors_dict(cors_dict)
                parsed_string = ','.join(parsed_list)
                fh.write(f'{url},{origin},{parsed_string}\n')
    else:
        print(f'[+] Writing to {csv_name}.')
        with open(csv_name, 'w') as fh:
            print()
            fh.write(','.join(col_headers) + '\n')
            for item in data:
                url = item[0]
                origin = item[1]
                cors_dict = item[2]
                parsed_list = parse_cors_dict(cors_dict)
                parsed_string = ','.join(parsed_list)
                fh.write(f'{url},{origin},{parsed_string}\n')
    print('[*] Complete!')


def parse_cors_response_headers(response):
    """Returns a dictionary of CORS response headers from
    a specified response object.
    """
    cors_response_headers = {}
    if 'Access-Control-Allow-Origin' in response.headers.keys():
        cors_response_headers['acao'] = response.headers.get('Access-Control-Allow-Origin').replace(',',';')
    if 'Access-Control-Allow-Credentials' in response.headers.keys():
        cors_response_headers['acac'] = response.headers.get('Access-Control-Allow-Credentials').replace(',',';')
    if 'Access-Control-Allow-Methods' in response.headers.keys():
        cors_response_headers['acam'] = response.headers.get('Access-Control-Allow-Methods').replace(',',';')
    if 'Access-Control-Allow-Headers' in response.headers.keys():
        cors_response_headers['acah'] = response.headers.get('Access-Control-Allow-Headers').replace(',',';')
    if 'Access-Control-Max-Age' in response.headers.keys():
        cors_response_headers['acma'] = response.headers.get('Access-Control-Max-Age').replace(',',';')
    if 'Access-Control-Expose-Headers' in response.headers.keys():
        cors_response_headers['aceh'] = response.headers.get('Access-Control-Expose-Headers').replace(',',';')
    return cors_response_headers


def make_request(sess, url):
    """Makes a request and returns a response object."""
    try: 
        return sess.get(url, verify=False)
    except Exception as e:
        if args.verbose:
            print(f'[-] An error occurred: {e}')
        return False


def existing_cors_policy(url):
    """Makes a request with the Origin header value set as the  
    host and checks to see if any ACAO or ACAC header values appear. 
    """
    origin = urlparse(url).netloc
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)


def null_origin(url):
    """Makes a request with a null origin header and checks 
    the response for CORS headers.
    """
    origin = 'null'
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)


def reflected_origin(url):
    """Makes a request with a random Origin header value and 
    checks to see if that value is echoed in the ACAO header. 
    Returns the ACAO header value or None.
    """
    random_string = ''.join(choice(ascii_lowercase) for i in range(12))
    origin = f"{random_string}.com"
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)


def scheme_origin(url):
    """Makes a request checking with the Origin header value as 
    HTTP or HTTPS, opposite of whatever the URL is, and prints the
    CORS headers."""
    scheme = urlparse(url).scheme
    if scheme == 'https':
        origin = f"http://{urlparse(url).netloc}"
    else:
        origin = f"https://{urlparse(url).netloc}"
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)


def mangled_front_origin(url):
    """Makes a request with the Origin header value with the regular 
    value prepended with 12 random characters and prints and CORS 
    response headers.
    """
    random_string = ''.join(choice(ascii_lowercase) for i in range(12))
    origin = f"{random_string}{urlparse(url).netloc}"
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)


def mangled_rear_origin(url):
    """Makes a request with the Origin header value with the regular 
    value appended with 12 random characters and prints and CORS 
    response headers.
    """
    random_string = ''.join(choice(ascii_lowercase) for i in range(12))
    origin = f"{urlparse(url).netloc.split(':')[0]}.{random_string}.{urlparse(url).netloc.split('.')[-1]}"
    s = build_request_object()
    s.headers['Origin'] = origin
    resp = make_request(s, url)
    if not resp: return
    cors_response_headers = parse_cors_response_headers(resp)
    if any(value != '' for value in cors_response_headers.values()):
        data.append((url, origin, cors_response_headers))
        if args.verbose:
            print_dict(origin, cors_response_headers)



def build_request_object():
    """Returns a session object with user specified data.
    """
    # Initialize a session object
    s = requests.Session()
    
    # Add a user agent from commandline options or select
    # a random user agent.
    #user_agent = args.useragent if args.useragent else get_random_useragent()
    user_agent = get_random_useragent()
    s.headers['User-Agent'] = user_agent
    
    # Parse and add cookies specified from commandline options
    if args.cookies:
        for item in cookie_list:
            domain_cookies = item[1]
            cookies = domain_cookies.split(';')
            for cookie in cookies:
                cookie_name = cookie.split('=')[0].lstrip()
                cookie_value = '='.join(cookie.split('=')[1:]).lstrip()
                s.cookies[cookie_name] = cookie_value
    
    # Add referer if specified by commandline options
    if args.referer:
        s.headers['Referer'] = args.referer
    
    # Add a proxy if specified by commandline options
    if args.proxy:
        s.proxies['http'] = args.proxy
        s.proxies['https'] = args.proxy
        
    # Add a custom header if specified
    if args.custom_header:
        cust_header = args.custom_header.split('~~~')[0]
        cust_value = args.custom_header.split('~~~')[1]
        s.headers[cust_header] = cust_value
    return s


def test_cors_policy(url):
    """Runs several tests on a URL, each making a request with 
    a different Origin header value. The responses are parsed and 
    written to a CSV file.
    """
    existing_cors_policy(url)
    null_origin(url)
    reflected_origin(url)
    scheme_origin(url)
    mangled_front_origin(url)
    mangled_rear_origin(url)

    if not args.verbose:
        # Update the status bar
        with print_lock:
            p_bar.update(counter + 1)


def manage_queue():
    """Manages the url queue and calls the test_cors_policy function"""
    while True:
        current_url = url_queue.get()
        test_cors_policy(current_url)
        url_queue.task_done()


def main():
    for i in range(args.threads):
        t = threading.Thread(target=manage_queue)
        t.daemon = True
        t.start()

    for current_url in urls:
        url_queue.put(current_url)

    url_queue.join()

    write_csv(data)
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-pr", "--proxy", 
                        help="specify a proxy to use (-pr 127.0.0.1:8080)")
    parser.add_argument("-ch", "--custom-header",
                        nargs="*",
                        help='specify a custom header and value,  delimited with ~~~. Example: -a "X-Custom-Header~~~Custom-Value"')
    parser.add_argument("-a", "--auth",
                        nargs="*",
                        help='specify a domain, and value delimited with ~~~. Example: -a "example.com~~~Bearer eyJhb..."')
    parser.add_argument("-c", "--cookies",
                        nargs="*",
                        help='specify a domain(s) and cookie(s) data delimited with ~~~. Example: -c "example.com~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I;" "http://example2.com:80~~~Token=19005936-1"')
    parser.add_argument("-ua", "--useragent", 
                        help="specify a User Agent string to use. Default is a random User Agent string.")
    parser.add_argument("-r", "--referer", 
                        help="specify a referer string to use.")
    parser.add_argument("-uf", "--url_file",
                        help="specify a file containing urls formatted http(s)://addr:port.")
    parser.add_argument("-u", "--url",
                        help="specify a single url formatted http(s)://addr:port.")
    parser.add_argument("-csv", "--csv_name",
                        help="specify a CSV file name. If the file already exists, the file will be appended to.")
    parser.add_argument("-t", "--threads",
                        nargs="?",
                        type=int,
                        const=10,
                        default=10,
                        help="specify number of threads (default=10)")
    parser.add_argument("-to", "--timeout",
                        nargs="?", 
                        type=int, 
                        default=10, 
                        help="specify number of seconds until a connection timeout (default=10)")
    args = parser.parse_args()

    # Suppress SSL warnings in the terminal
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Parse the urls
    if not args.url and not args.url_file:
        parser.print_help()
        print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf).\n")
        exit()
    if args.url and args.url_file:
        parser.print_help()
        print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf). Not both\n")
        exit()
    if args.url_file:
        url_file = args.url_file
        if not os.path.exists(url_file):
            print("\n[-] The file cannot be found or you do not have permission to open the file. Please check the path and try again\n")
            exit()
        urls = open(url_file).read().splitlines()
    if args.url:
        if not args.url.startswith('http'):
            parser.print_help()
            print("\n[-] Please specify a URL in the format proto://address:port (https://example.com:80).\n")
            exit()
        urls = [args.url]

    # Parses cookies
    if args.cookies:
        cookie_list = []
        for item in args.cookies:
            if '~~~' not in item:
                print('\n[-] Please specify the domain with the cookies using 3 tildes as a delimiter to separate the domain the cookie (-c "https://example.com:8443~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I; Token=19005936-1").\n')
                exit()
            cookie_domain = item.split('~~~')[0]
            cookies = item.split('~~~')[1]
            if cookie_domain.strip('/') not in [u.strip('/') for u in urls]:
                print('\n[-] Could not find {} in the URL list. Make sure to specify the domain in proto://domain:port format. Exiting.\n'.format(cookie_domain))
                exit()
            else:
                cookie_list.append((cookie_domain, cookies))

    # Threading lock and queue initialization
    print_lock = threading.Lock()
    url_queue = Queue()

    # Print banner and arguments
    print()
    word_banner = '{} version: {}. Coded by: {}'.format(sys.argv[0].title()[:-3], __version__, __author__)
    print('=' * len(word_banner))
    print(word_banner)
    print('=' * len(word_banner))
    print()
    for arg in vars(args):
        if getattr(args, arg):
            if arg == 'auth':
                continue
            print('{}: {}'.format(arg.title().replace('_',' '), getattr(args, arg)))
    print()
    time.sleep(3)

    if not args.verbose:
        # Initializes progress bar
        p_bar = tqdm.tqdm(range(len(urls)))
        counter = 0

    # Shared data variable
    data = []

    main()
