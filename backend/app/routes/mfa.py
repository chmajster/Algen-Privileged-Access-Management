from jose import JWTError, jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user, source_ip
from app.config import settings
from app.database import get_db
from app.mfa.challenge import create_challenge, verify_challenge, write_auth_event
from app.mfa.recovery_codes import generate_recovery_codes
from app.mfa.step_up import has_valid_step_up
from app.mfa.totp import encrypt_mfa_secret, generate_secret, provisioning_uri, verify_totp
from app.models import MfaChallenge, MfaRecoveryCode, StepUpSession, User, utcnow
from app.security import create_access_token


router = APIRouter(prefix="/api/mfa", tags=["mfa"])


def _challenge_or_404(db: DBSession, challenge_id: int, user_id: int | None = None) -> MfaChallenge:
    challenge = db.get(MfaChallenge, challenge_id)
    if not challenge or (user_id and challenge.user_id != user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MFA challenge not found")
    return challenge


def _user_from_mfa_token(db: DBSession, token: str) -> tuple[User, int | None]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        if payload.get("typ") != "mfa":
            raise JWTError("wrong token type")
        user = db.query(User).filter(User.username == payload.get("sub")).first()
        if not user:
            raise JWTError("user not found")
        return user, payload.get("challenge_id")
    except JWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA token") from exc


@router.get("/status", response_model=schemas.MfaStatusOut)
def mfa_status(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    remaining = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id, MfaRecoveryCode.used_at.is_(None)).count()
    return {
        "enabled": current_user.mfa_enabled,
        "required": current_user.mfa_required or (settings.pam_mfa_required_for_admin and current_user.role == "admin"),
        "enrolled_at": current_user.mfa_enrolled_at,
        "last_used_at": current_user.mfa_last_used_at,
        "recovery_codes_remaining": remaining,
    }


@router.post("/enroll/start", response_model=schemas.MfaEnrollStartOut)
def enroll_start(request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    secret = generate_secret()
    current_user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
    challenge = create_challenge(db, current_user, "step_up", "mfa_enroll", source_ip=source_ip(request), user_agent=request.headers.get("user-agent"))
    db.commit()
    return {"secret": secret, "provisioning_uri": provisioning_uri(secret, current_user.username), "challenge_id": challenge.id}


@router.post("/enroll/verify", response_model=schemas.Message)
def enroll_verify(payload: schemas.MfaVerifyIn, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if not current_user.mfa_secret_encrypted:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA enrollment not started")
    from app.mfa.totp import decrypt_mfa_secret

    if not verify_totp(decrypt_mfa_secret(current_user.mfa_secret_encrypted), payload.code):
        write_auth_event(db, "mfa_failed", user=current_user, success=False, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="MFA enrollment verification failed")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    current_user.mfa_enabled = True
    current_user.mfa_required = True
    current_user.mfa_enrolled_at = utcnow()
    current_user.mfa_last_used_at = utcnow()
    write_auth_event(db, "mfa_enrolled", user=current_user, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="MFA enrolled")
    db.commit()
    return {"message": "MFA enabled"}


@router.post("/verify", response_model=schemas.Token)
def verify(payload: schemas.MfaVerifyIn, request: Request, db: DBSession = Depends(get_db)):
    user = None
    challenge_id = payload.challenge_id
    if payload.mfa_token:
        user, token_challenge_id = _user_from_mfa_token(db, payload.mfa_token)
        challenge_id = challenge_id or token_challenge_id
    if not challenge_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "challenge_id is required")
    challenge = _challenge_or_404(db, challenge_id, user.id if user else None)
    if not verify_challenge(db, challenge, payload.code, recovery_code=payload.recovery_code):
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA code")
    user = user or db.get(User, challenge.user_id)
    user.last_login_at = utcnow()
    write_auth_event(db, "login_success" if challenge.challenge_type == "login" else "step_up_success", user=user, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message=f"MFA completed for {challenge.context}")
    db.commit()
    return schemas.Token(access_token=create_access_token(user.username), mfa_required=False, context=challenge.context, provider=user.auth_provider)


@router.post("/disable", response_model=schemas.Message)
def disable(payload: schemas.MfaDisableIn, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    from app.mfa.totp import decrypt_mfa_secret

    if current_user.mfa_secret_encrypted and not verify_totp(decrypt_mfa_secret(current_user.mfa_secret_encrypted), payload.code):
        write_auth_event(db, "mfa_failed", user=current_user, success=False, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="MFA disable failed")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    current_user.mfa_enabled = False
    current_user.mfa_secret_encrypted = None
    write_auth_event(db, "mfa_disabled", user=current_user, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="MFA disabled")
    db.commit()
    return {"message": "MFA disabled"}


@router.post("/recovery-codes/generate", response_model=schemas.RecoveryCodesOut)
def recovery_codes(request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    codes = generate_recovery_codes(db, current_user)
    write_auth_event(db, "mfa_recovery_codes_generated", user=current_user, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="Recovery codes generated")
    db.commit()
    return {"codes": codes}


@router.post("/recovery-codes/verify", response_model=schemas.Token)
def verify_recovery(payload: schemas.MfaVerifyIn, request: Request, db: DBSession = Depends(get_db)):
    payload.recovery_code = True
    return verify(payload, request, db)


@router.get("/challenges", response_model=list[schemas.MfaChallengeOut])
def challenges(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = db.query(MfaChallenge)
    if current_user.role != "admin":
        query = query.filter(MfaChallenge.user_id == current_user.id)
    return [schemas.MfaChallengeOut.model_validate(item).model_dump() for item in query.order_by(MfaChallenge.created_at.desc()).limit(200).all()]


@router.post("/step-up", response_model=schemas.MfaChallengeOut)
def step_up(payload: schemas.StepUpIn, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    challenge = create_challenge(db, current_user, "step_up", payload.context, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), metadata={"reason": payload.reason})
    db.commit()
    db.refresh(challenge)
    return schemas.MfaChallengeOut.model_validate(challenge).model_dump()


@router.get("/step-up/status", response_model=schemas.StepUpStatusOut)
def step_up_status(context: str, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = (
        db.query(StepUpSession)
        .filter(StepUpSession.user_id == current_user.id, StepUpSession.context == context, StepUpSession.valid_until >= utcnow())
        .order_by(StepUpSession.valid_until.desc())
        .first()
    )
    return {"context": context, "valid": has_valid_step_up(db, current_user, context), "valid_until": item.valid_until if item else None}
