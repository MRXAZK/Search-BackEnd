# routers/ocr.py
from fastapi.responses import JSONResponse
from fastapi import APIRouter,  UploadFile
from pydantic import BaseModel
import numpy as np
import io
import cv2
import pytesseract


class ImageType(BaseModel):
    url: str


ocr = APIRouter()


def read_img(img):
    text = pytesseract.image_to_string(img)
    return (text)


@ocr.post("/extract_text")
async def extract_text(file: UploadFile):
    label = ""
    if file:
        img = await file.read()
        image_stream = io.BytesIO(img)
        image_stream.seek(0)
        file_bytes = np.asarray(bytearray(image_stream.read()), dtype=np.uint8)
        frame = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        label = read_img(frame)

    return JSONResponse(content={"label": label})
