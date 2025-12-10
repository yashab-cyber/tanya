from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging
import json
import asyncio
from datetime import datetime
from app.core.config import settings

logger = logging.getLogger(__name__)


class BrowserManager:
    """Manages browser automation using Playwright"""

    def __init__(self):
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.har_path: Optional[str] = None

    async def initialize(self, record_har: bool = True, record_video: bool = False):
        """Initialize browser and context"""
        try:
            self.playwright = await async_playwright().start()

            # Launch browser
            self.browser = await self.playwright.chromium.launch(
                headless=settings.BROWSER_HEADLESS,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ],
            )

            # Setup HAR recording if enabled
            context_options = {
                "viewport": {
                    "width": settings.BROWSER_VIEWPORT_WIDTH,
                    "height": settings.BROWSER_VIEWPORT_HEIGHT,
                },
                "user_agent": settings.BROWSER_USER_AGENT,
                "ignore_https_errors": True,
            }
            
            if record_har:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.har_path = f"{settings.HAR_STORAGE_PATH}/scan_{timestamp}.har"
                Path(self.har_path).parent.mkdir(parents=True, exist_ok=True)
                context_options["record_har_path"] = self.har_path

            # Create context
            self.context = await self.browser.new_context(**context_options)

            # Create page
            self.page = await self.context.new_page()
            
            # Set timeouts
            self.page.set_default_timeout(settings.BROWSER_TIMEOUT)
            self.page.set_default_navigation_timeout(settings.BROWSER_NAVIGATION_TIMEOUT)

            logger.info("Browser initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Error initializing browser: {e}")
            return False

    async def navigate(self, url: str, wait_until: str = "networkidle") -> Dict[str, Any]:
        """Navigate to URL"""
        try:
            response = await self.page.goto(url, wait_until=wait_until)
            return {
                "success": True,
                "url": url,
                "status": response.status,
                "headers": response.headers,
            }
        except Exception as e:
            logger.error(f"Error navigating to {url}: {e}")
            return {"success": False, "error": str(e)}

    async def login(self, username: str, password: str) -> Dict[str, Any]:
        """Auto-detect and perform login"""
        try:
            # Wait for page to load
            await self.page.wait_for_load_state("networkidle")

            # Try to find login form elements
            username_selectors = [
                'input[type="text"]',
                'input[type="email"]',
                'input[name*="user"]',
                'input[name*="email"]',
                'input[id*="user"]',
                'input[id*="email"]',
                '#username',
                '#email',
            ]

            password_selectors = [
                'input[type="password"]',
                'input[name*="pass"]',
                'input[id*="pass"]',
                '#password',
            ]

            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
            ]

            # Fill username
            username_filled = False
            for selector in username_selectors:
                try:
                    await self.page.fill(selector, username, timeout=2000)
                    username_filled = True
                    logger.info(f"Filled username with selector: {selector}")
                    break
                except:
                    continue

            # Fill password
            password_filled = False
            for selector in password_selectors:
                try:
                    await self.page.fill(selector, password, timeout=2000)
                    password_filled = True
                    logger.info(f"Filled password with selector: {selector}")
                    break
                except:
                    continue

            # Click submit
            submitted = False
            for selector in submit_selectors:
                try:
                    await self.page.click(selector, timeout=2000)
                    submitted = True
                    logger.info(f"Clicked submit with selector: {selector}")
                    break
                except:
                    continue

            if username_filled and password_filled and submitted:
                # Wait for navigation
                await self.page.wait_for_load_state("networkidle", timeout=10000)
                return {"success": True, "message": "Login successful"}
            else:
                return {
                    "success": False,
                    "error": "Could not find login form elements",
                    "username_filled": username_filled,
                    "password_filled": password_filled,
                    "submitted": submitted,
                }

        except Exception as e:
            logger.error(f"Error during login: {e}")
            return {"success": False, "error": str(e)}

    async def screenshot(self, path: Optional[str] = None, full_page: bool = True) -> str:
        """Take screenshot"""
        try:
            if not path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                path = f"{settings.SCREENSHOT_STORAGE_PATH}/screenshot_{timestamp}.png"

            Path(path).parent.mkdir(parents=True, exist_ok=True)
            await self.page.screenshot(path=path, full_page=full_page)
            logger.info(f"Screenshot saved: {path}")
            return path

        except Exception as e:
            logger.error(f"Error taking screenshot: {e}")
            raise

    async def get_page_content(self) -> str:
        """Get current page HTML content"""
        return await self.page.content()

    async def get_all_urls(self) -> List[str]:
        """Extract all URLs from current page"""
        try:
            urls = await self.page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(link => link.href).filter(href => href);
                }
            """)
            return list(set(urls))  # Remove duplicates
        except Exception as e:
            logger.error(f"Error extracting URLs: {e}")
            return []

    async def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all forms from current page"""
        try:
            forms = await self.page.evaluate("""
                () => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map(form => ({
                        action: form.action,
                        method: form.method,
                        inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                            name: input.name,
                            type: input.type,
                            value: input.value
                        }))
                    }));
                }
            """)
            return forms
        except Exception as e:
            logger.error(f"Error extracting forms: {e}")
            return []

    async def extract_cookies(self) -> List[Dict[str, Any]]:
        """Extract all cookies"""
        try:
            cookies = await self.context.cookies()
            return cookies
        except Exception as e:
            logger.error(f"Error extracting cookies: {e}")
            return []

    async def click_element(self, selector: str) -> bool:
        """Click an element"""
        try:
            await self.page.click(selector)
            return True
        except Exception as e:
            logger.error(f"Error clicking element {selector}: {e}")
            return False

    async def type_text(self, selector: str, text: str) -> bool:
        """Type text into element"""
        try:
            await self.page.fill(selector, text)
            return True
        except Exception as e:
            logger.error(f"Error typing text into {selector}: {e}")
            return False

    async def wait_for_selector(self, selector: str, timeout: int = 5000) -> bool:
        """Wait for selector to appear"""
        try:
            await self.page.wait_for_selector(selector, timeout=timeout)
            return True
        except Exception as e:
            logger.error(f"Timeout waiting for {selector}: {e}")
            return False

    async def get_har_file(self) -> Optional[str]:
        """Get HAR file path"""
        return self.har_path

    async def close(self):
        """Close browser and cleanup"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("Browser closed successfully")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")
