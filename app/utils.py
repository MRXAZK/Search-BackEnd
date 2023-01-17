import random
import string
from passlib.context import CryptContext
from fastapi import Request
from geopy.geocoders import Nominatim
from requests import get


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


def generate_password_reset_code():
    # generate a random string of length 10
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))


def extract_device_info(request: Request):
    """
    Extract device information from request headers
    """
    user_agent = request.headers.get("User-Agent")
    language = request.headers.get("Accept-Language")
    
    # Get client's IP address
    ip_address = get('https://api.ipify.org').text
    
    # Use geopy to get latitude and longitude for IP address
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(ip_address, timeout=5)
    latitude = location.latitude
    longitude = location.longitude
    
    device = {"user_agent": user_agent, "language": language, "latitude": latitude, "longitude": longitude}
    return device
