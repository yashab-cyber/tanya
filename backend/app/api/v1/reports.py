from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.scan import Report
from app.tasks.scan_tasks import generate_report
from pydantic import BaseModel
from typing import List
from datetime import datetime

router = APIRouter()


class ReportCreate(BaseModel):
    scan_id: int
    report_type: str = "pdf"  # pdf, html, json


class ReportResponse(BaseModel):
    id: int
    scan_id: int
    report_type: str
    file_path: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=dict)
async def create_report(
    report_data: ReportCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new report"""
    # Trigger report generation task
    task = generate_report.delay(
        scan_id=report_data.scan_id,
        report_type=report_data.report_type
    )
    
    return {
        "message": "Report generation started",
        "task_id": task.id,
        "scan_id": report_data.scan_id,
        "report_type": report_data.report_type,
    }


@router.get("/scan/{scan_id}", response_model=List[ReportResponse])
async def get_reports(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get all reports for a scan"""
    result = await db.execute(
        select(Report).where(Report.scan_id == scan_id)
    )
    reports = result.scalars().all()
    
    return reports
