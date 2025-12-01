from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.tasks.scan_tasks import run_full_scan
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from datetime import datetime

router = APIRouter()


class ScanCreate(BaseModel):
    target_url: HttpUrl
    username: Optional[str] = None
    password: Optional[str] = None


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    total_urls: int
    total_apis: int
    total_js_files: int
    total_parameters: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(scan_data: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create and start a new scan"""
    try:
        # Create scan record
        scan = Scan(
            target_url=str(scan_data.target_url),
            username=scan_data.username,
            password=scan_data.password,
            status=ScanStatus.PENDING,
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Start scan task asynchronously
        run_full_scan.delay(
            scan_id=scan.id,
            target_url=str(scan_data.target_url),
            username=scan_data.username,
            password=scan_data.password,
        )

        return scan

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List all scans"""
    result = await db.execute(
        select(Scan).offset(skip).limit(limit).order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get scan by ID"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Delete scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await db.delete(scan)
    await db.commit()
    
    return None


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get detailed scan results"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "target_url": scan.target_url,
        "urls": scan.urls_discovered,
        "apis": scan.apis_discovered,
        "js_files": scan.js_files_discovered,
        "parameters": scan.parameters_discovered,
        "context_data": scan.context_data,
        "har_file": scan.har_file_path,
    }
