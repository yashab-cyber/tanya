from typing import Dict, Any, List, Optional
from app.services.claude_service import ClaudeService
import logging
import json

logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all AI agents"""

    def __init__(self):
        self.claude_service = ClaudeService()
        self.context = {}

    async def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute agent task - to be implemented by subclasses"""
        raise NotImplementedError


class PlanningAgent(BaseAgent):
    """Agent responsible for planning test strategies"""

    async def execute(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan comprehensive testing strategy based on scan results
        
        Args:
            scan_data: Dictionary containing URLs, APIs, parameters, etc.
            
        Returns:
            Testing plan with prioritized tests
        """
        try:
            logger.info("Planning Agent: Generating test strategy...")

            # Extract key information
            target_info = {
                "target_url": scan_data.get("target_url"),
                "urls_count": len(scan_data.get("urls", [])),
                "apis_count": len(scan_data.get("apis", [])),
                "parameters_count": len(scan_data.get("parameters", [])),
                "authentication": scan_data.get("has_authentication", False),
            }

            context = {
                "urls": scan_data.get("urls", [])[:20],  # Sample URLs
                "apis": scan_data.get("apis", [])[:20],  # Sample APIs
                "parameters": scan_data.get("parameters", [])[:50],  # Sample params
                "technologies": scan_data.get("technologies", []),
            }

            # Generate strategy using Claude
            result = await self.claude_service.generate_test_strategy(target_info, context)

            if result["success"]:
                try:
                    # Parse strategy (attempt to extract JSON from response)
                    strategy_text = result["strategy"]
                    # Try to find JSON in the response
                    if "{" in strategy_text and "}" in strategy_text:
                        start = strategy_text.find("{")
                        end = strategy_text.rfind("}") + 1
                        strategy_json = json.loads(strategy_text[start:end])
                    else:
                        # If no JSON, create structured response
                        strategy_json = {"plan": strategy_text, "tests": []}

                    return {
                        "success": True,
                        "strategy": strategy_json,
                        "raw_response": strategy_text,
                    }
                except json.JSONDecodeError:
                    # Fallback: return as text
                    return {
                        "success": True,
                        "strategy": {"plan": result["strategy"]},
                        "raw_response": result["strategy"],
                    }
            else:
                return result

        except Exception as e:
            logger.error(f"Planning Agent error: {e}")
            return {"success": False, "error": str(e)}


class ExecutionAgent(BaseAgent):
    """Agent responsible for executing tests"""

    async def execute(
        self, test_plan: Dict[str, Any], browser_manager: Any
    ) -> Dict[str, Any]:
        """
        Execute tests based on the plan
        
        Args:
            test_plan: Test strategy from Planning Agent
            browser_manager: Browser automation instance
            
        Returns:
            Test execution results
        """
        try:
            logger.info("Execution Agent: Running tests...")

            results = []
            tests = test_plan.get("tests", [])

            for test in tests:
                test_type = test.get("type")
                target = test.get("target")

                # Execute test based on type
                if test_type == "sql_injection":
                    result = await self._execute_sql_injection(target, browser_manager)
                elif test_type == "xss":
                    result = await self._execute_xss_test(target, browser_manager)
                elif test_type == "csrf":
                    result = await self._execute_csrf_test(target, browser_manager)
                else:
                    result = {"test": test, "status": "skipped", "reason": "Unknown test type"}

                results.append(result)

            return {"success": True, "results": results}

        except Exception as e:
            logger.error(f"Execution Agent error: {e}")
            return {"success": False, "error": str(e)}

    async def _execute_sql_injection(self, target: str, browser_manager: Any) -> Dict[str, Any]:
        """Execute SQL injection test"""
        # Implementation will be in VAPT testing modules
        return {"test_type": "sql_injection", "target": target, "status": "pending"}

    async def _execute_xss_test(self, target: str, browser_manager: Any) -> Dict[str, Any]:
        """Execute XSS test"""
        return {"test_type": "xss", "target": target, "status": "pending"}

    async def _execute_csrf_test(self, target: str, browser_manager: Any) -> Dict[str, Any]:
        """Execute CSRF test"""
        return {"test_type": "csrf", "target": target, "status": "pending"}


class AnalysisAgent(BaseAgent):
    """Agent responsible for analyzing test results"""

    async def execute(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze test results to identify vulnerabilities
        
        Args:
            test_results: List of test execution results
            
        Returns:
            Analysis with confirmed vulnerabilities
        """
        try:
            logger.info("Analysis Agent: Analyzing test results...")

            vulnerabilities = []
            false_positives = []

            for result in test_results:
                # Analyze each result using Claude
                analysis = await self.claude_service.analyze_vulnerability(
                    test_results=result,
                    request_data=result.get("request", {}),
                    response_data=result.get("response", {}),
                )

                if analysis["success"]:
                    try:
                        analysis_text = analysis["analysis"]
                        # Try to parse JSON from response
                        if "{" in analysis_text and "}" in analysis_text:
                            start = analysis_text.find("{")
                            end = analysis_text.rfind("}") + 1
                            analysis_data = json.loads(analysis_text[start:end])
                        else:
                            analysis_data = {"raw": analysis_text}

                        if analysis_data.get("is_vulnerable"):
                            vulnerabilities.append(
                                {
                                    "test_result": result,
                                    "analysis": analysis_data,
                                    "severity": analysis_data.get("severity", "medium"),
                                }
                            )
                        else:
                            false_positives.append(result)
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse analysis JSON for result: {result}")

            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "false_positives": false_positives,
                "total_tested": len(test_results),
                "total_vulnerable": len(vulnerabilities),
            }

        except Exception as e:
            logger.error(f"Analysis Agent error: {e}")
            return {"success": False, "error": str(e)}


class SelfHealingAgent(BaseAgent):
    """Agent responsible for adapting to UI changes"""

    async def execute(
        self, failed_action: Dict[str, Any], screenshot_path: str
    ) -> Dict[str, Any]:
        """
        Attempt to heal failed actions by analyzing current UI state
        
        Args:
            failed_action: The action that failed
            screenshot_path: Current screenshot path
            
        Returns:
            Alternative action or error recovery strategy
        """
        try:
            logger.info("Self-Healing Agent: Attempting to recover from failure...")

            prompt = f"""
            The following action failed: {failed_action}
            
            Looking at the current screenshot, please:
            1. Identify what might have caused the failure
            2. Suggest an alternative approach
            3. Provide new coordinates or selectors if needed
            
            Response should include: reason, alternative_action, confidence_score
            """

            result = await self.claude_service.analyze_screenshot(screenshot_path, prompt)

            if result["success"]:
                return {
                    "success": True,
                    "healing_suggestion": result["content"],
                    "original_action": failed_action,
                }
            else:
                return result

        except Exception as e:
            logger.error(f"Self-Healing Agent error: {e}")
            return {"success": False, "error": str(e)}


class AgentOrchestrator:
    """Orchestrates all agents for complete VAPT workflow"""

    def __init__(self):
        self.planning_agent = PlanningAgent()
        self.execution_agent = ExecutionAgent()
        self.analysis_agent = AnalysisAgent()
        self.self_healing_agent = SelfHealingAgent()

    async def run_full_scan(
        self, scan_data: Dict[str, Any], browser_manager: Any
    ) -> Dict[str, Any]:
        """
        Run complete VAPT scan using all agents
        
        Args:
            scan_data: Initial scan data (URLs, APIs, etc.)
            browser_manager: Browser automation instance
            
        Returns:
            Complete scan results with vulnerabilities
        """
        try:
            logger.info("Agent Orchestrator: Starting full scan workflow...")

            # Step 1: Planning
            plan_result = await self.planning_agent.execute(scan_data)
            if not plan_result["success"]:
                return plan_result

            # Step 2: Execution
            exec_result = await self.execution_agent.execute(
                plan_result["strategy"], browser_manager
            )
            if not exec_result["success"]:
                return exec_result

            # Step 3: Analysis
            analysis_result = await self.analysis_agent.execute(exec_result["results"])
            if not analysis_result["success"]:
                return analysis_result

            # Combine results
            return {
                "success": True,
                "plan": plan_result["strategy"],
                "test_results": exec_result["results"],
                "analysis": analysis_result,
                "vulnerabilities": analysis_result["vulnerabilities"],
                "summary": {
                    "total_tests": len(exec_result["results"]),
                    "vulnerabilities_found": len(analysis_result["vulnerabilities"]),
                    "false_positives": len(analysis_result["false_positives"]),
                },
            }

        except Exception as e:
            logger.error(f"Agent Orchestrator error: {e}")
            return {"success": False, "error": str(e)}
