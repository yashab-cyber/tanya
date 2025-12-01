from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.scan import TestResult, TestSeverity
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()


class TestResultResponse(BaseModel):
    id: int
    scan_id: int
    test_type: str
    test_name: str
    target_url: str
    is_vulnerable: bool
    severity: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/scan/{scan_id}", response_model=List[TestResultResponse])
async def get_test_results(
    scan_id: int,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get test results for a scan"""
    query = select(TestResult).where(TestResult.scan_id == scan_id)
    
    if severity:
        query = query.where(TestResult.severity == severity)
    
    result = await db.execute(query)
    test_results = result.scalars().all()
    
    return test_results


@router.get("/scan/{scan_id}/vulnerabilities", response_model=List[TestResultResponse])
async def get_vulnerabilities(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get only vulnerable findings for a scan"""
    result = await db.execute(
        select(TestResult).where(
            TestResult.scan_id == scan_id,
            TestResult.is_vulnerable == True
        )
    )
    vulnerabilities = result.scalars().all()
    
    return vulnerabilities


@router.get("/scan/{scan_id}/summary")
async def get_test_summary(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get summary of test results"""
    result = await db.execute(
        select(TestResult).where(TestResult.scan_id == scan_id)
    )
    all_results = result.scalars().all()
    
    vulnerabilities = [r for r in all_results if r.is_vulnerable]
    
    summary = {
        "total_tests": len(all_results),
        "total_vulnerabilities": len(vulnerabilities),
        "critical": len([v for v in vulnerabilities if v.severity == TestSeverity.CRITICAL]),
        "high": len([v for v in vulnerabilities if v.severity == TestSeverity.HIGH]),
        "medium": len([v for v in vulnerabilities if v.severity == TestSeverity.MEDIUM]),
        "low": len([v for v in vulnerabilities if v.severity == TestSeverity.LOW]),
        "info": len([v for v in vulnerabilities if v.severity == TestSeverity.INFO]),
    }
    
    return summary
