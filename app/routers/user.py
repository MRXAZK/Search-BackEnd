# routes/user.py
import base64
import datetime
import time
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from ..database import get_db
from sqlalchemy.orm import Session
from .. import models, schemas, oauth2
from app.routers.ocr import collection

router = APIRouter()


@router.get('/me', response_model=schemas.UserResponse)
def get_me(db: Session = Depends(get_db), user_id: str = Depends(oauth2.require_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    return user


@router.get("/dashboard")
async def dashboard(db: Session = Depends(get_db), user_id: int = Depends(oauth2.require_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    username = user.username
    full_name = user.full_name
    data = list(collection.find({"data.user_id": user_id}))
    date_upload = []
    for doc in data:
        for item in doc["data"]:
            date_upload.append(
                item["timestamp"].strftime("%Y-%m-%d %H:%M:%S"))
            data_count = len(item)
        if data_count == 0:
            date_upload = None
    return JSONResponse(content={"username": username, "full_name": full_name, "total_data": data_count, "date_upload": date_upload})
