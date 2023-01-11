# routes/user.py

import base64
from io import BytesIO
from fastapi import APIRouter, Depends, UploadFile, HTTPException, File
from bson import ObjectId
from ..database import get_db
from sqlalchemy.orm import Session
from .. import models, schemas, oauth2

router = APIRouter()


@router.get('/me', response_model=schemas.UserResponse)
def get_me(db: Session = Depends(get_db), user_id: str = Depends(oauth2.require_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    return user
