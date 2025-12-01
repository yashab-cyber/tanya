from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from app.agents.browser_manager import BrowserManager
import logging
import asyncio
import re
import json
from collections import defaultdict

logger = logging.getLogger(__name__)


class CrawlerEngine:
    """Advanced web crawler for URL discovery"""

    def __init__(self, browser_manager: BrowserManager, max_depth: int = 5, max_urls: int = 10000):
        self.browser_manager = browser_manager
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.queue: List[tuple] = []  # (url, depth)

    async def crawl(self, start_url: str) -> Dict[str, Any]:
        """
        Crawl website starting from start_url
        
        Returns:
            Dictionary with discovered URLs, depth map, etc.
        """
        try:
            logger.info(f"Starting crawl from: {start_url}")
            
            base_domain = urlparse(start_url).netloc
            self.queue.append((start_url, 0))
            self.discovered_urls.add(start_url)

            depth_map = defaultdict(list)
            url_metadata = {}

            while self.queue and len(self.visited_urls) < self.max_urls:
                url, depth = self.queue.pop(0)

                if url in self.visited_urls or depth > self.max_depth:
                    continue

                logger.info(f"Crawling: {url} (depth: {depth})")
                self.visited_urls.add(url)
                depth_map[depth].append(url)

                # Navigate to URL
                nav_result = await self.browser_manager.navigate(url)
                if not nav_result["success"]:
                    logger.warning(f"Failed to navigate to {url}")
                    continue

                # Wait a bit for dynamic content
                await asyncio.sleep(0.1)

                # Extract metadata
                url_metadata[url] = {
                    "status": nav_result.get("status"),
                    "depth": depth,
                    "timestamp": nav_result.get("timestamp"),
                }

                # Extract all links from page
                new_urls = await self.browser_manager.get_all_urls()

                for new_url in new_urls:
                    # Only crawl URLs from same domain
                    if urlparse(new_url).netloc == base_domain:
                        if new_url not in self.discovered_urls:
                            self.discovered_urls.add(new_url)
                            self.queue.append((new_url, depth + 1))

            logger.info(f"Crawl completed. Discovered {len(self.discovered_urls)} URLs")

            return {
                "success": True,
                "total_urls": len(self.discovered_urls),
                "visited_urls": len(self.visited_urls),
                "urls": list(self.discovered_urls),
                "depth_map": dict(depth_map),
                "metadata": url_metadata,
            }

        except Exception as e:
            logger.error(f"Error during crawl: {e}")
            return {"success": False, "error": str(e)}


class APIExtractor:
    """Extract API endpoints from various sources"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.discovered_apis: Set[str] = set()
        self.api_details: List[Dict[str, Any]] = []

    async def extract_from_har(self, har_path: str) -> List[Dict[str, Any]]:
        """Extract API calls from HAR file"""
        try:
            with open(har_path, 'r') as f:
                har_data = json.load(f)

            apis = []
            for entry in har_data.get('log', {}).get('entries', []):
                request = entry.get('request', {})
                response = entry.get('response', {})
                
                url = request.get('url', '')
                method = request.get('method', '')
                
                # Check if this looks like an API endpoint
                if self._is_api_endpoint(url):
                    api_info = {
                        'url': url,
                        'method': method,
                        'status': response.get('status'),
                        'headers': request.get('headers', []),
                        'query_params': request.get('queryString', []),
                        'post_data': request.get('postData', {}),
                        'response_content_type': next(
                            (h['value'] for h in response.get('headers', []) 
                             if h['name'].lower() == 'content-type'),
                            None
                        ),
                    }
                    apis.append(api_info)
                    self.discovered_apis.add(url)

            logger.info(f"Extracted {len(apis)} API endpoints from HAR")
            return apis

        except Exception as e:
            logger.error(f"Error extracting APIs from HAR: {e}")
            return []

    def _is_api_endpoint(self, url: str) -> bool:
        """Determine if URL is likely an API endpoint"""
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/ws/',
            r'\.json',
            r'/ajax/',
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    async def extract_from_js(self, js_content: str) -> List[str]:
        """Extract API endpoints from JavaScript code"""
        try:
            # Common API endpoint patterns in JS
            patterns = [
                r'["\']https?://[^"\']+["\']',  # Full URLs
                r'["\'][/][a-zA-Z0-9/_-]+["\']',  # Relative paths
                r'fetch\(["\']([^"\']+)["\']',  # Fetch API
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',  # Axios
                r'\.get\(["\']([^"\']+)["\']',  # .get() calls
                r'\.post\(["\']([^"\']+)["\']',  # .post() calls
            ]

            endpoints = set()
            for pattern in patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                endpoints.update(matches)

            return list(endpoints)

        except Exception as e:
            logger.error(f"Error extracting APIs from JS: {e}")
            return []


class JSAnalyzer:
    """Analyze JavaScript files for security issues and endpoints"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.js_files: List[Dict[str, Any]] = []

    async def discover_js_files(self, har_path: str) -> List[str]:
        """Discover all JavaScript files from HAR"""
        try:
            with open(har_path, 'r') as f:
                har_data = json.load(f)

            js_files = []
            for entry in har_data.get('log', {}).get('entries', []):
                request = entry.get('request', {})
                response = entry.get('response', {})
                
                url = request.get('url', '')
                content_type = next(
                    (h['value'] for h in response.get('headers', []) 
                     if h['name'].lower() == 'content-type'),
                    ''
                )

                # Check if this is a JS file
                if url.endswith('.js') or 'javascript' in content_type.lower():
                    js_files.append({
                        'url': url,
                        'size': response.get('bodySize', 0),
                        'content': response.get('content', {}).get('text', ''),
                    })

            logger.info(f"Discovered {len(js_files)} JavaScript files")
            return js_files

        except Exception as e:
            logger.error(f"Error discovering JS files: {e}")
            return []

    async def analyze_js_file(self, js_content: str) -> Dict[str, Any]:
        """Analyze JavaScript file for security issues"""
        try:
            analysis = {
                'api_keys': [],
                'secrets': [],
                'endpoints': [],
                'sensitive_patterns': [],
            }

            # Look for API keys
            api_key_patterns = [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]

            for pattern in api_key_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                analysis['api_keys'].extend(matches)

            # Look for hardcoded secrets
            secret_patterns = [
                r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'aws[_-]?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]

            for pattern in secret_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                analysis['secrets'].extend(matches)

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing JS file: {e}")
            return {}


class ParameterExtractor:
    """Extract parameters from forms, URLs, and APIs"""

    def __init__(self):
        self.parameters: Dict[str, List[Any]] = defaultdict(list)

    async def extract_from_forms(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract parameters from HTML forms"""
        params = []
        for form in forms:
            for input_field in form.get('inputs', []):
                param = {
                    'name': input_field.get('name'),
                    'type': input_field.get('type'),
                    'form_action': form.get('action'),
                    'form_method': form.get('method'),
                    'source': 'form',
                }
                params.append(param)
                self.parameters[input_field.get('name')].append(param)
        
        return params

    async def extract_from_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract parameters from URL query strings"""
        params = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parsed.query.split('&')
                for param in query_params:
                    if '=' in param:
                        key, value = param.split('=', 1)
                        param_info = {
                            'name': key,
                            'example_value': value,
                            'url': url,
                            'source': 'url',
                        }
                        params.append(param_info)
                        self.parameters[key].append(param_info)
        
        return params

    async def extract_from_apis(self, apis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract parameters from API calls"""
        params = []
        for api in apis:
            # Extract from query params
            for param in api.get('query_params', []):
                param_info = {
                    'name': param.get('name'),
                    'value': param.get('value'),
                    'api_url': api.get('url'),
                    'method': api.get('method'),
                    'source': 'api_query',
                }
                params.append(param_info)

            # Extract from POST data
            post_data = api.get('post_data', {})
            if post_data.get('params'):
                for param in post_data['params']:
                    param_info = {
                        'name': param.get('name'),
                        'value': param.get('value'),
                        'api_url': api.get('url'),
                        'method': api.get('method'),
                        'source': 'api_body',
                    }
                    params.append(param_info)

        return params

    def get_unique_parameters(self) -> List[str]:
        """Get list of unique parameter names"""
        return list(self.parameters.keys())


class ScanOrchestrator:
    """Orchestrates the complete scanning process"""

    def __init__(self, target_url: str, username: str = None, password: str = None):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.browser_manager = BrowserManager()
        self.crawler = None
        self.api_extractor = None
        self.js_analyzer = None
        self.param_extractor = ParameterExtractor()

    async def run_full_scan(self) -> Dict[str, Any]:
        """Run complete scanning workflow"""
        try:
            logger.info(f"Starting full scan for: {self.target_url}")

            # Initialize browser
            await self.browser_manager.initialize(record_har=True)

            # Navigate to target
            await self.browser_manager.navigate(self.target_url)

            # Login if credentials provided
            if self.username and self.password:
                login_result = await self.browser_manager.login(self.username, self.password)
                logger.info(f"Login result: {login_result}")

            # Initialize components
            self.crawler = CrawlerEngine(self.browser_manager)
            self.api_extractor = APIExtractor(self.browser_manager)
            self.js_analyzer = JSAnalyzer(self.browser_manager)

            # Step 1: Crawl website
            logger.info("Step 1: Crawling website...")
            crawl_result = await self.crawler.crawl(self.target_url)
            
            urls = crawl_result.get('urls', [])
            logger.info(f"Discovered {len(urls)} URLs")

            # Step 2: Get HAR file and extract APIs
            logger.info("Step 2: Extracting API endpoints...")
            har_path = await self.browser_manager.get_har_file()
            apis = []
            if har_path:
                apis = await self.api_extractor.extract_from_har(har_path)
            logger.info(f"Discovered {len(apis)} API endpoints")

            # Step 3: Discover and analyze JS files
            logger.info("Step 3: Analyzing JavaScript files...")
            js_files = []
            if har_path:
                js_files = await self.js_analyzer.discover_js_files(har_path)
            logger.info(f"Discovered {len(js_files)} JS files")

            # Step 4: Extract parameters
            logger.info("Step 4: Extracting parameters...")
            
            # Extract forms
            forms = await self.browser_manager.extract_forms()
            form_params = await self.param_extractor.extract_from_forms(forms)
            
            # Extract from URLs
            url_params = await self.param_extractor.extract_from_urls(urls)
            
            # Extract from APIs
            api_params = await self.param_extractor.extract_from_apis(apis)
            
            all_params = form_params + url_params + api_params
            unique_params = self.param_extractor.get_unique_parameters()
            
            logger.info(f"Discovered {len(unique_params)} unique parameters")

            # Step 5: Extract cookies
            cookies = await self.browser_manager.extract_cookies()

            # Compile results
            scan_results = {
                "success": True,
                "target_url": self.target_url,
                "urls": urls,
                "total_urls": len(urls),
                "apis": apis,
                "total_apis": len(apis),
                "js_files": [js['url'] for js in js_files],
                "total_js_files": len(js_files),
                "parameters": all_params,
                "unique_parameters": unique_params,
                "total_parameters": len(unique_params),
                "forms": forms,
                "cookies": cookies,
                "har_file": har_path,
                "has_authentication": bool(self.username),
            }

            logger.info("Full scan completed successfully")
            return scan_results

        except Exception as e:
            logger.error(f"Error during full scan: {e}")
            return {"success": False, "error": str(e)}

        finally:
            # Cleanup
            await self.browser_manager.close()
