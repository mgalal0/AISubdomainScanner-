import socket
import json
import sys
import time
import platform
import subprocess
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set
import threading
import queue
import os
import random
import string
import re
from urllib.parse import urlparse
import itertools
import collections
import pickle
import traceback
import dns.resolver
import dns.zone
import dns.query
import urllib3

# Disable SSL warnings
urllib3.disable_warnings()

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SubdomainKnowledgeBase:
    def __init__(self, base_path="./knowledge_base"):
        self.base_path = base_path
        self.patterns_file = os.path.join(base_path, "patterns.pkl")
        self.domains_file = os.path.join(base_path, "domains.json")
        self.patterns = collections.defaultdict(int)  # Initialize as defaultdict
        self.known_domains = collections.defaultdict(set)
        self.load_knowledge()

    def update_pattern(self, pattern: str, increment: int = 1):
        """Safely update pattern count."""
        if pattern and isinstance(pattern, str):
            self.patterns[pattern] += increment

    def add_domain(self, main_domain: str, subdomain: str):
        """Safely add a subdomain to known domains."""
        if main_domain and subdomain:
            self.known_domains[main_domain].add(subdomain)

    def load_knowledge(self):
        """Load existing knowledge base."""
        os.makedirs(self.base_path, exist_ok=True)
        
        # Load patterns
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, 'rb') as f:
                    loaded_patterns = pickle.load(f)
                    # Convert loaded data to defaultdict
                    self.patterns = collections.defaultdict(int, loaded_patterns)
                print(f"{Colors.BLUE}[+] Loaded {len(self.patterns)} known patterns{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error loading patterns: {str(e)}{Colors.ENDC}")
                self.patterns = collections.defaultdict(int)

        # Load known domains
        if os.path.exists(self.domains_file):
            try:
                with open(self.domains_file, 'r') as f:
                    domain_data = json.load(f)
                    for domain, subdomains in domain_data.items():
                        self.known_domains[domain] = set(subdomains)
                print(f"{Colors.BLUE}[+] Loaded data for {len(self.known_domains)} domains{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error loading domains: {str(e)}{Colors.ENDC}")
                self.known_domains = collections.defaultdict(set)

    def save_knowledge(self):
        """Save current knowledge base."""
        try:
            os.makedirs(self.base_path, exist_ok=True)
            
            # Save patterns
            with open(self.patterns_file, 'wb') as f:
                pickle.dump(dict(self.patterns), f)
            
            # Save domains
            domain_data = {domain: list(subdomains) 
                          for domain, subdomains in self.known_domains.items()}
            with open(self.domains_file, 'w') as f:
                json.dump(domain_data, f, indent=4)
            
            print(f"{Colors.BLUE}[+] Knowledge base saved successfully{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error saving knowledge base: {str(e)}{Colors.ENDC}")

class IntelligentSubdomainDiscovery:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.knowledge_base = SubdomainKnowledgeBase()
        self.found_subdomains = set()
        self.subdomain_queue = queue.Queue()
        self.MAX_THREADS = 100
        self.TIMEOUT = 3
        self.learning_rounds = 5
        self.results = {
            "domain": target_domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subdomains": [],
            "patterns": {},
            "statistics": {}
        }

        # Banner
        self.banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════╗
║                AI-Powered DNS Analysis Tool v5.0                ║
║                Created by: Mahmoud Galal                       ║
║                  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                    ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""

    def extract_patterns_from_domain(self, subdomain: str) -> List[str]:
        """Extract meaningful patterns from a subdomain."""
        try:
            patterns = []
            if not subdomain:
                return patterns
                
            # Split domain into parts
            parts = re.split(r'[.-]', subdomain)
            
            # Add single parts
            patterns.extend(part for part in parts if part)
            
            # Add combinations
            for i in range(len(parts) - 1):
                if parts[i] and parts[i+1]:
                    patterns.append(f"{parts[i]}-{parts[i+1]}")
                    patterns.append(f"{parts[i]}{parts[i+1]}")
            
            # Extract number patterns
            for part in parts:
                if part:
                    num_pattern = re.sub(r'\d+', 'N', part)
                    if num_pattern != part:
                        patterns.append(num_pattern)
            
            return list(set(patterns))  # Remove duplicates
        except Exception:
            return []

    def generate_mutations(self) -> Set[str]:
        """Generate intelligent mutations for subdomain discovery."""
        mutations = set()
    
        try:
            # Expanded common patterns
            common_patterns = [
                # Infrastructure patterns
                'www', 'dev', 'api', 'admin', 'test', 'stage', 'staging', 'prod', 
                'app', 'apps', 'web', 'mail', 'smtp', 'pop3', 'imap', 'ftp', 'sftp',
                'ssh', 'remote', 'ns1', 'ns2', 'ns', 'dns', 'mx', 'proxy', 'vpn', 
                'cloud', 'cdn', 'static', 'media', 'files', 'storage',

                # Development and testing
                'jenkins', 'ci', 'build', 'beta', 'alpha', 'testing', 'integration',
                'sandbox', 'uat', 'qa', 'preview', 'dev-api', 'test-api', 'staging-api',
                'development', 'internal', 'external', 'demo', 'pilot',

                # Services and applications
                'jira', 'confluence', 'wiki', 'docs', 'documentation', 'support',
                'help', 'helpdesk', 'service-desk', 'ticket', 'status', 'health',
                'monitor', 'grafana', 'kibana', 'elk', 'logging', 'log', 'metrics',
                'prometheus', 'alerts', 'dashboard', 'analytics', 'stats',

                # Security and access
                'auth', 'login', 'sso', 'ldap', 'vpn', 'gateway', 'proxy', 'waf',
                'firewall', 'security', 'secure', 'admin', 'administrator',
                'mgmt', 'management', 'control', 'panel', 'cpanel', 'whm',

                # Content and media
                'blog', 'forum', 'community', 'shop', 'store', 'cart', 'checkout',
                'pay', 'payment', 'billing', 'invoice', 'order', 'catalog',
                'img', 'images', 'video', 'media', 'assets', 'static', 'cdn',
                'content', 'download', 'uploads', 'files',

                # Database and storage
                'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo',
                'elasticsearch', 'solr', 'backup', 'store', 'storage', 'cache',
                
                # Regional and location-based
                'eu', 'us', 'asia', 'america', 'europe', 'africa', 'oceania',
                'north', 'south', 'east', 'west', 'central',
                
                # Environment indicators
                'prod', 'production', 'dev', 'development', 'stage', 'staging',
                'test', 'testing', 'qa', 'uat', 'int', 'integration', 'demo',
                
                # Corporate functions
                'corp', 'corporate', 'hr', 'finance', 'sales', 'marketing',
                'research', 'legal', 'compliance', 'partners', 'vendor',
                
                # Mobile and API related
                'mobile', 'android', 'ios', 'app', 'api', 'api-docs', 'swagger',
                'graphql', 'rest', 'soap', 'ws', 'websocket', 'socket',
            ]
            mutations.update(common_patterns)
        
            # Add patterns from knowledge base with weights
            weighted_patterns = sorted(
                self.knowledge_base.patterns.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:100]  # Take top 100 patterns
        
            for pattern, count in weighted_patterns:
                if count > 0:
                    mutations.add(pattern)
                    # Generate variations with numbers
                    if 'N' in pattern:
                        for i in range(1, 21):  # Extended range
                            mutations.add(pattern.replace('N', str(i)))
        
            # Add known subdomains for this domain
            if self.target_domain in self.knowledge_base.known_domains:
                mutations.update(self.knowledge_base.known_domains[self.target_domain])
        
            # Generate advanced combinations
            environments = ['dev', 'test', 'staging', 'prod', 'uat', 'qa']
            services = ['api', 'app', 'web', 'admin', 'portal', 'dashboard']
            regions = ['eu', 'us', 'asia', 'au']
            numbers = list(range(1, 11))
        
            # Create combinations
            for env in environments:
                for service in services:
                    mutations.add(f"{env}-{service}")
                    mutations.add(f"{service}-{env}")
                    for region in regions:
                        mutations.add(f"{env}-{service}-{region}")
                        mutations.add(f"{region}-{env}-{service}")
                    
            # Generate numbered variations
            base_patterns = ['server', 'host', 'node', 'srv', 'web', 'app', 'worker']
            for base in base_patterns:
                for num in numbers:
                    mutations.add(f"{base}{num}")
                    mutations.add(f"{base}-{num}")
                    for env in environments:
                        mutations.add(f"{base}{num}-{env}")
                        mutations.add(f"{env}-{base}{num}")
        
            # Add date-based patterns
            current_year = datetime.now().year
            years = range(current_year-5, current_year+1)
            for year in years:
                mutations.add(str(year))
                for env in environments:
                    mutations.add(f"{env}-{year}")
                    mutations.add(f"{year}-{env}")
        
            # Generate cloud-specific patterns
            cloud_providers = ['aws', 'azure', 'gcp']
            cloud_services = ['s3', 'blob', 'storage', 'cdn', 'cache']
            for provider in cloud_providers:
                for service in cloud_services:
                    mutations.add(f"{provider}-{service}")
                    mutations.add(f"{service}-{provider}")
        
            print(f"{Colors.BLUE}[+] Generated {len(mutations)} mutations to test{Colors.ENDC}")
            return mutations
        
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error generating mutations: {str(e)}{Colors.ENDC}")
            return set()

    def discover_new_patterns(self) -> Set[str]:
        """Discover new subdomain patterns through various techniques."""
        new_patterns = set()
    
        try:
            # 1. Certificate Transparency Logs
            ct_domains = self._check_certificate_logs()
            new_patterns.update(ct_domains)
        
            # 2. DNS Zone Transfer attempt
            zone_domains = self._try_zone_transfer()
            new_patterns.update(zone_domains)
        
            # 3. Search engine discovery
            search_domains = self._search_engine_discovery()
            new_patterns.update(search_domains)
        
            # Learn from discovered patterns
            for subdomain in new_patterns:
                patterns = self.extract_patterns_from_domain(subdomain)
                for pattern in patterns:
                    self.knowledge_base.update_pattern(pattern)
        
            return new_patterns
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error in pattern discovery: {str(e)}{Colors.ENDC}")
            return set()

    def _check_certificate_logs(self) -> Set[str]:
        """Check Certificate Transparency logs for subdomains."""
        domains = set()
        ct_urls = [
            f"https://crt.sh/?q=%.{self.target_domain}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={self.target_domain}&include_subdomains=true&expand=dns_names"
        ]
    
        for url in ct_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        for entry in data:
                            if 'name_value' in entry:
                                name = entry['name_value']
                            elif 'dns_names' in entry:
                                name = entry['dns_names'][0]
                            else:
                                continue
                            
                            if name.endswith(self.target_domain):
                                subdomain = name[:-len(self.target_domain)-1]
                                if subdomain:
                                    domains.add(subdomain)
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error checking CT logs: {str(e)}{Colors.ENDC}")
    
        return domains

    def _try_zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer."""
        domains = set()
    
        try:
            # Find nameservers
            answers = dns.resolver.resolve(self.target_domain, 'NS')
            nameservers = [str(rdata.target) for rdata in answers]
        
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.target_domain))
                    if zone:
                        for name, node in zone.nodes.items():
                            name_str = str(name)
                            if name_str and name_str != '@':
                                domains.add(name_str)
                except:
                    continue
        except Exception as e:
            print(f"{Colors.WARNING}[!] Zone transfer failed: {str(e)}{Colors.ENDC}")
    
        return domains

    def _search_engine_discovery(self) -> Set[str]:
        """Discover subdomains through search engine results."""
        domains = set()
    
        # Common dorks for finding subdomains
        dorks = [
            f"site:*.{self.target_domain}",
            f"site:*.*.{self.target_domain}",
            f"site:*.{self.target_domain} -www",
        ]
    
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
        for dork in dorks:
            try:
                search_url = f"https://www.google.com/search?q={dork}"
                response = requests.get(search_url, headers=headers, timeout=10, verify=False)
            
                if response.status_code == 200:
                    # Extract domains using regex
                    pattern = f"[a-zA-Z0-9.-]+\.{re.escape(self.target_domain)}"
                    found = re.findall(pattern, response.text)
                
                    for domain in found:
                        if domain.endswith(self.target_domain):
                            subdomain = domain[:-len(self.target_domain)-1]
                            if subdomain:
                                domains.add(subdomain)
                            
                time.sleep(2)  # Respect rate limits
            
            except Exception as e:
                print(f"{Colors.WARNING}[!] Search engine discovery error: {str(e)}{Colors.ENDC}")
    
        return domains

    def run_scan(self):
        """Run the main scanning process with enhanced discovery."""
        print(f"{Colors.BLUE}[+] Starting intelligent subdomain discovery for {self.target_domain}...{Colors.ENDC}")
    
        # Initial discovery phase
        print(f"{Colors.BLUE}[+] Starting initial pattern discovery...{Colors.ENDC}")
        discovered_patterns = self.discover_new_patterns()
        if discovered_patterns:
            print(f"{Colors.GREEN}[✓] Found {len(discovered_patterns)} initial patterns{Colors.ENDC}")
        
        round_number = 0
        total_found = 0
        consecutive_empty_rounds = 0
    
        while round_number < self.learning_rounds and consecutive_empty_rounds < 3:
            round_number += 1
            print(f"\n{Colors.BLUE}[+] Starting round {round_number}/{self.learning_rounds}{Colors.ENDC}")
        
            # Generate mutations including discovered patterns
            mutations = self.generate_mutations()
            mutations.update(discovered_patterns)
        
            if not mutations:
                consecutive_empty_rounds += 1
                continue
            
            # Fill the queue
            for mutation in mutations:
                self.subdomain_queue.put(mutation)
        
            # Start worker threads
            threads = []
            thread_count = min(self.MAX_THREADS, len(mutations))
            for _ in range(thread_count):
                t = threading.Thread(target=self.scan_worker)
                t.daemon = True
                t.start()
                threads.append(t)
        
            # Wait for completion
            self.subdomain_queue.join()
        
            # Save progress
            self.knowledge_base.save_knowledge()
        
            # Check progress
            new_found = len(self.found_subdomains) - total_found
            total_found = len(self.found_subdomains)
        
            if new_found > 0:
                consecutive_empty_rounds = 0
                # Try to discover new patterns based on findings
                if round_number % 2 == 0:  # Every other round
                    print(f"{Colors.BLUE}[+] Attempting to discover new patterns...{Colors.ENDC}")
                    new_discovered = self.discover_new_patterns()
                    if new_discovered:
                        discovered_patterns.update(new_discovered)
                        print(f"{Colors.GREEN}[✓] Found {len(new_discovered)} new patterns{Colors.ENDC}")
            else:
                consecutive_empty_rounds += 1
                print(f"{Colors.WARNING}[!] No new subdomains found in round {round_number}{Colors.ENDC}")
        
            print(f"{Colors.GREEN}[✓] Round {round_number} complete: Found {new_found} new subdomains{Colors.ENDC}")
        
            # Extend rounds if finding new subdomains
            if new_found > 0:
                self.learning_rounds = min(self.learning_rounds + 2, 20)
        
            # Update scan statistics
            self.results["statistics"].update({
                "current_round": round_number,
                "total_found": total_found,
                "discovered_patterns": len(discovered_patterns),
                "mutations_tested": len(mutations)
            })
        
            time.sleep(1)  # Brief pause between rounds
    
        # Process final results
        self.results["subdomains"] = [json.loads(s) for s in self.found_subdomains]
        self.results["statistics"].update({
            "total_rounds": round_number,
            "total_found": len(self.results["subdomains"]),
            "learned_patterns": len(self.knowledge_base.patterns),
            "final_discovered_patterns": len(discovered_patterns)
        })
    
        # Save final knowledge base
        self.knowledge_base.save_knowledge()
    
        print(f"\n{Colors.GREEN}[✓] Scan completed after {round_number} rounds{Colors.ENDC}")
        print(f"{Colors.BLUE}[+] Total subdomains found: {len(self.results['subdomains'])}{Colors.ENDC}")
        print(f"{Colors.BLUE}[+] Total patterns learned: {len(self.knowledge_base.patterns)}{Colors.ENDC}")
        print(f"{Colors.BLUE}[+] Total patterns discovered: {len(discovered_patterns)}{Colors.ENDC}")

    def verify_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Verify subdomain existence using multiple methods."""
        full_domain = f"{subdomain}.{self.target_domain}"
        
        try:
            # Method 1: DNS resolution
            try:
                ip = socket.gethostbyname(full_domain)
                return {"host": full_domain, "ip": ip, "method": "DNS", "pattern": subdomain}
            except socket.gaierror:
                pass

            # Method 2: HTTPS request
            try:
                response = requests.get(
                    f"https://{full_domain}",
                    timeout=self.TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
                if response.status_code < 404:
                    return {"host": full_domain, "ip": "HTTPS", "method": "HTTPS", "pattern": subdomain}
            except:
                pass

            # Method 3: HTTP request
            try:
                response = requests.get(
                    f"http://{full_domain}",
                    timeout=self.TIMEOUT,
                    allow_redirects=True
                )
                if response.status_code < 404:
                    return {"host": full_domain, "ip": "HTTP", "method": "HTTP", "pattern": subdomain}
            except:
                pass

        except Exception:
            pass
        
        return None

    def scan_worker(self):
        """Worker function for scanning subdomains."""
        while True:
            try:
                subdomain = self.subdomain_queue.get_nowait()
            except queue.Empty:
                break
            
            try:
                result = self.verify_subdomain(subdomain)
                if result:
                    self.found_subdomains.add(json.dumps(result))
                    print(f"{Colors.GREEN}[✓] Found: {result['host']} ({result['method']}){Colors.ENDC}")
                    
                    # Learn from success
                    patterns = self.extract_patterns_from_domain(subdomain)
                    for pattern in patterns:
                        if pattern:  # Make sure pattern is not empty
                            self.knowledge_base.update_pattern(pattern)
                    self.knowledge_base.add_domain(self.target_domain, subdomain)
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error in worker thread: {str(e)}{Colors.ENDC}")
            finally:
                self.subdomain_queue.task_done()

    def run_analysis(self) -> Dict[str, any]:
        """Run the complete analysis."""
        print(self.banner)
        
        try:
            # Run the main scan
            self.run_scan()
            
            # Save final report
            report_name = f"{self.target_domain}_analysis_{int(time.time())}.json"
            with open(report_name, 'w') as f:
                json.dump(self.results, f, indent=4)
            
            print(f"\n{Colors.GREEN}[✓] Analysis complete!{Colors.ENDC}")
            print(f"{Colors.BLUE}[+] Found {len(self.results['subdomains'])} subdomains{Colors.ENDC}")
            print(f"{Colors.BLUE}[+] Learned {len(self.knowledge_base.patterns)} patterns{Colors.ENDC}")
            print(f"{Colors.GREEN}[✓] Report saved to: {report_name}{Colors.ENDC}")
            
            return self.results
            
        except Exception as e:
            print(f"{Colors.FAIL}[×] Error during analysis: {str(e)}{Colors.ENDC}")
            traceback.print_exc()
            self.knowledge_base.save_knowledge()  # Save knowledge even on error
            raise

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.FAIL}Usage: python dns_analyzer.py domain.com{Colors.ENDC}")
        sys.exit(1)

    domain = sys.argv[1]
    analyzer = IntelligentSubdomainDiscovery(domain)
    
    try:
        results = analyzer.run_analysis()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Analysis interrupted by user{Colors.ENDC}")
        analyzer.knowledge_base.save_knowledge()  # Save knowledge even on interrupt
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[×] Error during analysis: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()