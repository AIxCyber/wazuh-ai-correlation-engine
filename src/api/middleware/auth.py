
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from src.core.config import get_config
from src.core.database import get_db
from src.core.models.orm_models import PasswordResetToken, User

security_scheme = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "analyst": [
        "view_incidents", "view_alerts", "run_analysis",
        "export_reports", "view_dashboard",
    ],
    "senior_analyst": [
        "view_incidents", "view_alerts", "run_analysis",
        "export_reports", "view_dashboard",
        "adjust_scores", "merge_incidents", "split_incidents",
        "manage_webhooks", "add_notes",
    ],
    "admin": [
        "view_incidents", "view_alerts", "run_analysis",
        "export_reports", "view_dashboard",
        "adjust_scores", "merge_incidents", "split_incidents",
        "manage_webhooks", "add_notes",
        "manage_dlq", "manage_users", "view_config",
        "delete_data",
    ],
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def create_access_token(user_id: str, role: str) -> str:
    cfg = get_config()
    expire = datetime.now(UTC) + timedelta(minutes=cfg.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "role": role,
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, cfg.jwt_secret, algorithm=cfg.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    cfg = get_config()
    try:
        return jwt.decode(token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> dict[str, Any] | None:
    if credentials is None:
        return None
    payload = decode_token(credentials.credentials)
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.active:
        return None
    return {"id": user.id, "username": user.username, "role": user.role}


def require_permission(permission: str):
    async def permission_checker(
        current_user: dict[str, Any] | None = Depends(get_current_user),
    ) -> dict[str, Any]:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        user_permissions = ROLE_PERMISSIONS.get(current_user["role"], [])
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return current_user
    return permission_checker


def login_user(username: str, password: str, db: Session) -> dict[str, Any] | None:
    user = db.query(User).filter(User.username == username, User.active.is_(True)).first()
    if user and verify_password(password, user.hashed_password):
        token = create_access_token(user.id, user.role)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": get_config().jwt_expire_minutes * 60,
            "password_change_required": user.force_password_change,
        }
    return None


def change_password(user_id: str, old_password: str, new_password: str, db: Session) -> bool:
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not verify_password(old_password, user.hashed_password):
        return False
    if old_password == new_password or verify_password(new_password, user.hashed_password):
        return False
    user.hashed_password = hash_password(new_password)
    user.force_password_change = False
    user.password_changed_at = datetime.now(UTC)
    db.commit()
    return True


def reset_password(target_user_id: str, new_password: str, db: Session) -> bool:
    user = db.query(User).filter(User.id == target_user_id).first()
    if not user:
        return False
    user.hashed_password = hash_password(new_password)
    user.force_password_change = True
    db.commit()
    return True


def generate_reset_token(username: str, db: Session) -> str | None:
    user = db.query(User).filter(User.username == username, User.active.is_(True)).first()
    if not user:
        return None
    token = secrets.token_hex(4)
    expires_at = datetime.now(UTC) + timedelta(minutes=15)
    reset = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.add(reset)
    db.commit()
    return token


def reset_password_with_token(token: str, new_password: str, db: Session) -> str | None:
    now = datetime.now(UTC)
    record = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token == token,
            PasswordResetToken.used.is_(False),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not record:
        return None
    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        return None
    user.hashed_password = hash_password(new_password)
    user.force_password_change = True
    record.used = True
    db.commit()
    return user.username
