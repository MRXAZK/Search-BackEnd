from pymongo import mongo_client
import pymongo
from app.config import settings

client = pymongo.MongoClient(
    f"mongodb://{settings.MONGO_INITDB_ROOT_USERNAME}:{settings.MONGO_INITDB_ROOT_PASSWORD}@localhost:{settings.MONGO_INITDB_PORT}/{settings.MONGO_INITDB_DATABASE}?authSource=admin")
db = client[settings.MONGO_INITDB_DATABASE]
print('Connected to MongoDB...')
User = db[f"{settings.MONGO_INITDB_COLLECTION_USER}"]
OCR = db[f"{settings.MONGO_INITDB_COLLECTION_OCR}"]
User.create_index([("email", pymongo.ASCENDING)], unique=True)
