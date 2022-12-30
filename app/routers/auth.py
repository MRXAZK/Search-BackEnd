from datetime import timedelta
import datetime
import hashlib
from random import randbytes
import re
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr

# Importing necessary modules and dependencies

from app import oauth2
from .. import schemas, models, utils
from sqlalchemy.orm import Session
from ..database import get_db
from app.oauth2 import AuthJWT, require_user
from ..config import settings
from ..email import Email

# Importing application modules and dependencies

router = APIRouter()

# Initializing the API router

ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN

# Storing the access token and refresh token expiration durations in variables


@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(payload: schemas.CreateUserSchema, request: Request, db: Session = Depends(get_db)):
    # Check if user or username already exist
    user_query = db.query(models.User).filter(
        models.User.email == EmailStr(payload.email.lower()))
    user = user_query.first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail='Email already exist')
    username_query = db.query(models.User).filter(
        models.User.username == payload.username)
    username = username_query.first()
    if username:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail='Username already exist')
    # Compare password and passwordConfirm
    if payload.password != payload.passwordConfirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')
    #  Hash the password
    payload.password = utils.hash_password(payload.password)
    del payload.passwordConfirm
    payload.role = 'user'
    payload.verified = False
    payload.email = EmailStr(payload.email.lower())
    new_user = models.User(**payload.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        # Send Verification Email
        token = randbytes(10)
        hashedCode = hashlib.sha256()
        hashedCode.update(token)
        verification_code = hashedCode.hexdigest()
        user_query.update(
            {'verification_code': verification_code}, synchronize_session=False)
        db.commit()
        url = f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verifyemail/{token.hex()}"
        await Email(new_user, url, [payload.email]).sendVerificationCode()
    except Exception as error:
        print('Error', error)
        user_query.update(
            {'verified': True, 'verification_code': None}, synchronize_session=False)
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')
    return {'status': 'success', 'message': 'Verification token successfully sent to your email'}


@router.post('/login')
def login(payload: schemas.LoginUserSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    # Check if the user exist
    user = db.query(models.User).filter(
        models.User.email == EmailStr(payload.email.lower())).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # Check if user verified his email
    if not user.verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    # Check if the password is valid
    if not utils.verify_password(payload.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # Create access token
    access_token = Authorize.create_access_token(
        subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))

    # Create refresh token
    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # Send both access
    return {'status': 'success', 'access_token': access_token}

# User email verification endpoint


@router.get('/verifyemail/{token}')
def verify_email(token: str, db: Session = Depends(get_db)):
    # Check if the token is correct
    user = db.query(models.User).filter(
        models.User.verification_code == hashlib.sha256(bytes.fromhex(token)).hexdigest()).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Invalid token')

    # Set the user's verification_code field to None and verified field to True
    user.verification_code = None
    user.verified = True
    db.commit()
    return {'status': 'success', 'message': 'Email verified'}


@router.get('/refresh')
def refresh_token(response: Response, request: Request, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no logger exist')
        access_token = Authorize.create_access_token(
            subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {'access_token': access_token}


@router.post('/resetpasswordrequest')
async def reset_password_request(payload: schemas.ResetPasswordRequestSchema, request: Request, db: Session = Depends(get_db)):
    # Check if the user exist
    user = db.query(models.User).filter(
        models.User.email == EmailStr(payload.email.lower())).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Email not found')

    # Check if user verified his email
    if not user.verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    try:
        # Send Password Reset Email
        token = randbytes(10)
        hashedCode = hashlib.sha256()
        hashedCode.update(token)
        password_reset_code = hashedCode.hexdigest()
        user.password_reset_code = password_reset_code
        user.password_reset_code_expiry = datetime.datetime.utcnow() + \
            timedelta(minutes=30)
        db.commit()
        # url = f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/resetpassword/{token.hex()}"
        url = token.hex()
        await Email(user, url, [payload.email]).sendPasswordResetCode()
    except Exception as error:
        print('Error', error)
        user.password_reset_code = None
        user.password_reset_code_expiry = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')
    return {'status': 'success', 'message': 'Password reset code successfully sent to your email'}


@router.post('/resetpassword/{token}')
def reset_password(token: str, payload: schemas.ResetPasswordSchema, db: Session = Depends(get_db)):
    # Check if the token is valid
    hashedCode = hashlib.sha256()
    hashedCode.update(bytes.fromhex(token))
    password_reset_code = hashedCode.hexdigest()
    user = db.query(models.User).filter(
        models.User.password_reset_code == password_reset_code).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Invalid token')

    # Check if the token has expired
    if user.password_reset_code_expiry < datetime.datetime.utcnow():
        user.password_reset_code = None
        user.password_reset_code_expiry = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Token has expired')

    # Compare password and passwordConfirm
    if payload.password != payload.passwordConfirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    # Check that the new password is not the same as the current password
    if utils.verify_password(payload.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='New password cannot be the same as the current password')

    # Hash the new password
    payload.password = utils.hash_password(payload.password)

    # Update the user's password in the database
    user.password = payload.password
    user.password_reset_code = None
    user.password_reset_code_expiry = None
    db.commit()

    return {'status': 'success', 'message': 'Password successfully reset'}


@router.post('/changepassword')
def change_password(payload: schemas.ChangePasswordSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    user_id = require_user(db, Authorize)
    user = db.query(models.User).filter(models.User.id == user_id).first()

    # Check if the current password is correct
    if not utils.verify_password(payload.currentPassword, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect current password')

    # Check if the new password and passwordConfirm match
    if payload.newPassword != payload.passwordConfirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    # Check that the new password is not the same as the current password
    if utils.verify_password(payload.newPassword, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='New password cannot be the same as the current password')

    # Hash the new password
    payload.newPassword = utils.hash_password(payload.newPassword)

    # Update the user's password in the database
    user.password = payload.newPassword

    db.commit()

    return {'status': 'success', 'message': 'Password successfully changed'}


@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(oauth2.require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}
