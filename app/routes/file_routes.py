from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import User, FileRecord, AnalysisResult
from app.auth import get_current_user
from app.services.static_analysis import analyze_file

router = APIRouter(prefix="/files", tags=["File Analysis"])


@router.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    file_bytes = file.file.read()
    result = analyze_file(file_bytes)

    file_record = FileRecord(
        filename=file.filename,
        md5_hash=result["md5"],
        sha256_hash=result["sha256"],
        file_size=result["file_size"],
        owner_id=current_user.id,
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    analysis = AnalysisResult(
        file_id=file_record.id,
        risk_score=result["risk_score"],
        classification=result["classification"],
        yara_matches=", ".join(result["keywords"]),
    )
    db.add(analysis)
    db.commit()

    return {
        "filename": file_record.filename,
        "md5": file_record.md5_hash,
        "sha256": file_record.sha256_hash,
        "risk_score": result["risk_score"],
        "classification": result["classification"],
        "keywords_found": result["keywords"],
        "urls_found": result["urls"],
    }
@router.get("/")
def list_my_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    records = db.query(FileRecord).filter(FileRecord.owner_id == current_user.id).all()
    output = []
    for r in records:
        output.append({
            "filename": r.filename,
            "sha256": r.sha256_hash,
            "uploaded_at": r.uploaded_at,
            "risk_score": r.analysis.risk_score if r.analysis else None,
            "classification": r.analysis.classification if r.analysis else None,
        })
    return output