"""Init file for models package"""
from app.models.scan import Scan, TestResult, Report, ScanStatus, TestSeverity
from app.models.user import User

__all__ = ["Scan", "TestResult", "Report", "ScanStatus", "TestSeverity", "User"]
