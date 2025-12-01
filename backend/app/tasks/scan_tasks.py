from app.celery_app import celery_app
from app.scanners.scan_engine import ScanOrchestrator
from app.agents.ai_agents import AgentOrchestrator
from app.testers.vapt_testers import VAPTTestOrchestrator
from app.agents.browser_manager import BrowserManager
from sqlalchemy import select
from app.models.scan import Scan, ScanStatus, TestResult, TestSeverity
from app.core.database import AsyncSessionLocal
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.run_full_scan")
def run_full_scan(self, scan_id: int, target_url: str, username: str = None, password: str = None):
    """Celery task to run full scan asynchronously"""
    import asyncio
    
    async def _run_scan():
        db = AsyncSessionLocal()
        try:
            # Update scan status
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            logger.info(f"Starting scan {scan_id} for {target_url}")

            # Step 1: Run initial scan
            orchestrator = ScanOrchestrator(target_url, username, password)
            scan_result = await orchestrator.run_full_scan()

            if not scan_result["success"]:
                scan.status = ScanStatus.FAILED
                scan.error_message = scan_result.get("error")
                await db.commit()
                return

            # Update scan with results
            scan.urls_discovered = scan_result.get("urls", [])
            scan.apis_discovered = scan_result.get("apis", [])
            scan.js_files_discovered = scan_result.get("js_files", [])
            scan.parameters_discovered = scan_result.get("parameters", [])
            scan.total_urls = scan_result.get("total_urls", 0)
            scan.total_apis = scan_result.get("total_apis", 0)
            scan.total_js_files = scan_result.get("total_js_files", 0)
            scan.total_parameters = scan_result.get("total_parameters", 0)
            scan.har_file_path = scan_result.get("har_file")
            scan.context_data = scan_result
            await db.commit()

            # Step 2: Run AI agent orchestration for test planning
            browser_manager = BrowserManager()
            await browser_manager.initialize()
            
            try:
                agent_orchestrator = AgentOrchestrator()
                agent_result = await agent_orchestrator.run_full_scan(scan_result, browser_manager)

                # Step 3: Run VAPT tests
                vapt_orchestrator = VAPTTestOrchestrator(browser_manager)
                vapt_result = await vapt_orchestrator.run_all_tests(scan_result)

                # Save test results
                if vapt_result["success"]:
                    all_test_results = vapt_result["results"]
                    
                    for test_type, results in all_test_results.items():
                        for result in results:
                            if result.get("vulnerable"):
                                # Determine severity
                                severity = TestSeverity.MEDIUM
                                if test_type == "sql_injection":
                                    severity = TestSeverity.CRITICAL
                                elif test_type in ["authentication_bypass", "idor"]:
                                    severity = TestSeverity.HIGH

                                test_result = TestResult(
                                    scan_id=scan_id,
                                    test_type=test_type,
                                    test_name=f"{test_type}_test",
                                    target_url=result.get("url", result.get("test_url", target_url)),
                                    is_vulnerable=True,
                                    severity=severity,
                                    payload=str(result.get("payload", "")),
                                    request_data=result,
                                    evidence=str(result),
                                )
                                db.add(test_result)

                await db.commit()

            finally:
                await browser_manager.close()

            # Mark scan as completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            await db.commit()

            logger.info(f"Scan {scan_id} completed successfully")

        except Exception as e:
            logger.error(f"Error in scan {scan_id}: {e}", exc_info=True)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                await db.commit()
        finally:
            await db.close()

    # Run async function
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_scan())
    finally:
        loop.close()


@celery_app.task(name="app.tasks.generate_report")
def generate_report(scan_id: int, report_type: str = "pdf"):
    """Generate report for scan"""
    logger.info(f"Generating {report_type} report for scan {scan_id}")
    # Report generation will be implemented in reporting module
    return {"scan_id": scan_id, "report_type": report_type, "status": "completed"}
