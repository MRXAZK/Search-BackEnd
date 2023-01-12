from fastapi import APIRouter, UploadFile, Depends
from fastapi.responses import JSONResponse
from typing import List
from app import oauth2
import pymongo
import cv2
import io
import numpy as np
import pytesseract
from datetime import datetime
from app.config import settings


ocr = APIRouter()

client = pymongo.MongoClient(
    f"mongodb://{settings.MONGO_INITDB_ROOT_USERNAME}:{settings.MONGO_INITDB_ROOT_PASSWORD}@localhost:{settings.MONGO_INITDB_PORT}/{settings.MONGO_INITDB_DATABASE}?authSource=admin")
db = client[settings.MONGO_INITDB_DATABASE]
collection = db["ocr"]


def read_img(img):
    text = pytesseract.image_to_string(img)
    return (text)


@ocr.post("/extract_text")
async def extract_text(files: List[UploadFile], user_id: int = Depends(oauth2.require_user)):
    images_data = []
    extracted_texts = []
    for file in files:
        img = await file.read()
        image_stream = io.BytesIO(img)
        image_stream.seek(0)
        file_bytes = np.asarray(bytearray(image_stream.read()), dtype=np.uint8)
        frame = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        label = read_img(frame)
        extracted_texts.append(label)
        data = {
            "user_id": user_id,
            "text": label,
            "timestamp": datetime.now()
        }
        images_data.append(data)
    collection.update_many(
        {}, {"$push": {"data": {"$each": images_data}}}, upsert=True)
    return JSONResponse(content={"extracted_texts": extracted_texts})
