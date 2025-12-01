from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Enum as SQLEnum
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(2048), nullable=False)
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    
    # Status
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    # Results
    urls_discovered = Column(JSON, default=list)
    apis_discovered = Column(JSON, default=list)
    js_files_discovered = Column(JSON, default=list)
    parameters_discovered = Column(JSON, default=list)
    
    # Metadata
    har_file_path = Column(String(512), nullable=True)
    screenshots_path = Column(String(512), nullable=True)
    context_data = Column(JSON, default=dict)
    
    # Statistics
    total_urls = Column(Integer, default=0)
    total_apis = Column(Integer, default=0)
    total_js_files = Column(Integer, default=0)
    total_parameters = Column(Integer, default=0)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class TestSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestResult(Base):
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    
    # Test details
    test_type = Column(String(100), nullable=False)
    test_name = Column(String(255), nullable=False)
    target_url = Column(String(2048), nullable=False)
    
    # Results
    is_vulnerable = Column(Boolean, default=False)
    severity = Column(SQLEnum(TestSeverity), nullable=True)
    
    # Details
    payload = Column(Text, nullable=True)
    request_data = Column(JSON, nullable=True)
    response_data = Column(JSON, nullable=True)
    evidence = Column(Text, nullable=True)
    screenshot_path = Column(String(512), nullable=True)
    
    # Remediation
    remediation = Column(Text, nullable=True)
    cve_references = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    
    # Report details
    report_type = Column(String(50), nullable=False)  # pdf, html, json
    file_path = Column(String(512), nullable=False)
    
    # Summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
