import re
import sys
from colorama import Fore, Style

# Top open redirect parameters
open_redirect_params = [
    "page", "url", "ret", "r2", "img", "u", "return", "r", "URL", "next", "redirect",
    "redirectBack", "AuthState", "referer", "redir", "l", "aspxerrorpath", "image_path",
    "ActionCodeURL", "return_url", "link", "q", "location", "ReturnUrl", "uri", "referrer",
    "returnUrl", "forward", "file", "rb", "end_display", "urlact", "from", "goto", "path",
    "redirect_url", "old", "pathlocation", "successTarget", "returnURL", "urlsito", "newurl",
    "Url", "back", "retour", "odkazujuca_linka", "r_link", "cur_url", "H_name", "ref", "topic",
    "resource", "returnTo", "home", "node", "sUrl", "href", "linkurl", "returnto", "redirecturl",
    "SL", "st", "errorUrl", "media", "destination", "targeturl", "return_to", "cancel_url", "doc",
    "GO", "ReturnTo", "anything", "FileName", "logoutRedirectURL", "list", "startUrl", "service",
    "redirect_to", "end_url", "_next", "noSuchEntryRedirect", "context", "returnurl", "ref_url"
]

def highlight_vulnerable_params(urls):
    for url in urls:
        for param in open_redirect_params:
            if re.search(fr"[?&]{param}=", url):
                print(Fore.GREEN + url + Style.RESET_ALL)
                break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python open_redirect_checker.py <urls_file>")
        sys.exit(1)

    urls_file = sys.argv[1]

    try:
        with open(urls_file, "r") as file:
            urls = file.readlines()
            highlight_vulnerable_params([url.strip() for url in urls])
    except FileNotFoundError:
        print(f"Error: File '{urls_file}' not found.")
        sys.exit(1)
