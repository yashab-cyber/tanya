from anthropic import Anthropic
from app.core.config import settings
from typing import Dict, List, Any, Optional
import logging
import base64
from pathlib import Path

logger = logging.getLogger(__name__)


class ClaudeService:
    """Service for interacting with Anthropic Claude API"""

    def __init__(self):
        self.client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.model = settings.ANTHROPIC_MODEL
        self.max_tokens = settings.ANTHROPIC_MAX_TOKENS

    async def analyze_screenshot(
        self, screenshot_path: str, prompt: str, context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze screenshot using Claude's vision capabilities"""
        try:
            # Read screenshot
            with open(screenshot_path, "rb") as f:
                screenshot_data = base64.standard_b64encode(f.read()).decode("utf-8")

            # Prepare messages
            messages = []
            if context:
                messages.append({"role": "user", "content": context})

            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": screenshot_data,
                            },
                        },
                        {"type": "text", "text": prompt},
                    ],
                }
            )

            # Call Claude API
            response = self.client.messages.create(
                model=self.model, max_tokens=self.max_tokens, messages=messages
            )

            return {"success": True, "content": response.content[0].text, "response": response}

        except Exception as e:
            logger.error(f"Error analyzing screenshot: {e}")
            return {"success": False, "error": str(e)}

    async def computer_use_action(
        self,
        screenshot_path: str,
        objective: str,
        display_width: int = None,
        display_height: int = None,
    ) -> Dict[str, Any]:
        """Use Computer Use API for browser automation"""
        try:
            width = display_width or settings.DISPLAY_WIDTH_PX
            height = display_height or settings.DISPLAY_HEIGHT_PX

            # Read screenshot
            with open(screenshot_path, "rb") as f:
                screenshot_data = base64.standard_b64encode(f.read()).decode("utf-8")

            # Call Computer Use API
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                tools=[
                    {
                        "type": "computer_20250124",
                        "name": "computer",
                        "display_width_px": width,
                        "display_height_px": height,
                        "display_number": settings.DISPLAY_NUMBER,
                    }
                ],
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": screenshot_data,
                                },
                            },
                            {"type": "text", "text": objective},
                        ],
                    }
                ],
                betas=[settings.ANTHROPIC_BETA_VERSION],
            )

            return {"success": True, "response": response}

        except Exception as e:
            logger.error(f"Error in computer use action: {e}")
            return {"success": False, "error": str(e)}

    async def generate_test_strategy(
        self, target_info: Dict[str, Any], scan_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate testing strategy using AI"""
        try:
            prompt = f"""
            Based on the following target information and scan context, generate a comprehensive 
            vulnerability testing strategy:

            Target Information:
            {target_info}

            Scan Context:
            {scan_context}

            Please provide:
            1. Prioritized list of vulnerabilities to test
            2. Testing approach for each vulnerability type
            3. Specific payloads or test cases to use
            4. Expected indicators of vulnerabilities
            5. Risk assessment

            Format the response as JSON.
            """

            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            return {"success": True, "strategy": response.content[0].text}

        except Exception as e:
            logger.error(f"Error generating test strategy: {e}")
            return {"success": False, "error": str(e)}

    async def analyze_vulnerability(
        self, test_results: Dict[str, Any], request_data: Dict[str, Any], response_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze potential vulnerability using AI"""
        try:
            prompt = f"""
            Analyze the following test results to determine if a vulnerability exists:

            Test Results: {test_results}
            Request Data: {request_data}
            Response Data: {response_data}

            Provide:
            1. Is this a confirmed vulnerability? (Yes/No)
            2. Severity level (Critical/High/Medium/Low/Info)
            3. Detailed explanation
            4. Proof of concept
            5. Remediation steps
            6. Relevant CVE references if applicable

            Format the response as JSON with keys: is_vulnerable, severity, explanation, poc, remediation, cve_refs
            """

            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            return {"success": True, "analysis": response.content[0].text}

        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {e}")
            return {"success": False, "error": str(e)}
