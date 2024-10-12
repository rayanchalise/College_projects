import sys
import concurrent.futures
from urllib.parse import urlparse

def is_interesting_url(url):
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()

    interesting_paths = ['/admin', '/login', '/dashboard', '/wp-admin', '/wp-login.php',
                         '/administrator', '/user', '/profile', '/config', '/backup',
                         '/test', '/phpinfo.php', '/info.php', '/setup', '/install',
                         '/console', '/api', '/oauth', '/secure', '/checkout',
                         '/payment', '/upload', '/download', '/reset', '/register',
                         '/newsletter', '/subscribe', '/feedback', '/contact',
                         '/support', '/help', '/about', '/terms', '/privacy',
                         '/legal', '/report', '/feedback.php', '/feedback.html',
                         '/contact-us', '/contact-us.php', '/contact-us.html',
                         '/search', '/search.php', '/search.html', '/blog',
                         '/blog.php', '/blog.html', '/news', '/news.php',
                         '/news.html', '/article', '/article.php', '/article.html',
                         '/product', '/product.php', '/product.html', '/category',
                         '/category.php', '/category.html', '/faq', '/faq.php',
                         '/faq.html', '/forum', '/forum.php', '/forum.html',
                         '/feedback', '/feedback.php', '/feedback.html',
                         '/account', '/account.php', '/account.html', '/checkout',
                         '/checkout.php', '/checkout.html', '/cart', '/cart.php',
                         '/cart.html', '/invoice', '/invoice.php', '/invoice.html',
                         '/order', '/order.php', '/order.html', '/reservation',
                         '/reservation.php', '/reservation.html', '/calendar',
                         '/calendar.php', '/calendar.html', '/event', '/event.php',
                         '/event.html', '/download', '/download.php', '/download.html',
                         '/upload', '/upload.php', '/upload.html', '/api']

    interesting_params = ['id', 'user', 'username', 'password', 'email', 'token',
                          'session', 'auth', 'apikey', 'access_token', 'refresh_token',
                          'admin', 'root', 'debug', 'cmd', 'command', 'exec', 'ping',
                          'url', 'redirect', 'return', 'callback', 'next', 'return_url',
                          'callback_url', 'redirect_uri', 'source', 'target', 'path',
                          'file', 'upload', 'download', 'delete', 'action', 'method',
                          'mode', 'lang', 'locale', 'currency', 'country', 'city',
                          'state', 'province', 'zipcode', 'postcode', 'search', 'query',
                          'filter', 'sort', 'order', 'category', 'tag', 'type', 'format',
                          'extension', 'style', 'theme', 'color', 'background', 'font',
                          'size', 'width', 'height', 'length', 'depth', 'weight', 'price',
                          'amount', 'quantity', 'rate', 'discount', 'coupon', 'voucher',
                          'referral', 'partner', 'affiliate', 'campaign', 'utm_source',
                          'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                          'gclid', 'msclkid', 'fbclid', 'cid', 'pid', 'sid', 'eid', 'aid',
                          'mid', 'gid', 'lid', 'fid', 'tid', 'vid', 'qid', 'zid']

    # Check if URL matches any interesting paths or parameters
    if any(path.startswith(ip) for ip in interesting_paths):
        return True
    if any(param in query for param in interesting_params):
        return True

    return False

def filter_interesting_urls(input_file, output_file):
    interesting_urls = []

    with open(input_file, 'r') as f:
        urls = f.readlines()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(is_interesting_url, url.strip()): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                if future.result():
                    interesting_urls.append(url)
            except Exception as e:
                print(f"Error processing {url}: {e}")

    with open(output_file, 'w') as f:
        for url in interesting_urls:
            f.write(url + '\n')

    print(f"Filtered {len(interesting_urls)} interesting URLs. Output saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python Wayintresting.py input_file.txt output_file.txt OR echo 'https://website.com?=' | python3 Wayintresting.py output.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    filter_interesting_urls(input_file, output_file)
