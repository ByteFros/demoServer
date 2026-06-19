from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User
from app.auth.repository import RefreshTokenRepository, UserRepository
from app.core.config import settings
from app.core.security import hash_token

VALID_PASSWORD = "StrongPass1!"


def user_payload(suffix: str = "one") -> dict[str, str]:
    return {
        "email": f"user-{suffix}@example.com",
        "username": f"user_{suffix}",
        "password": VALID_PASSWORD,
        "first_name": "Test",
        "last_name": "User",
    }


def auth_header(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


async def register_user(client: AsyncClient, suffix: str = "one") -> dict[str, str]:
    payload = user_payload(suffix)
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 201
    return payload


async def login_user(
    client: AsyncClient,
    email: str,
    password: str = VALID_PASSWORD,
) -> dict[str, Any]:
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()


async def get_user_by_email(db_session: AsyncSession, email: str) -> User:
    user = await UserRepository(db_session).get_by_email(email)
    assert user is not None
    return user


async def test_register_success_returns_public_user(client: AsyncClient) -> None:
    response = await client.post("/auth/register", json=user_payload("register"))

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "user-register@example.com"
    assert "hashed_password" not in body
    assert "is_verified" not in body


async def test_register_duplicate_email_returns_409(client: AsyncClient) -> None:
    payload = await register_user(client, "duplicate_email")
    duplicate = user_payload("other_email")
    duplicate["email"] = payload["email"]

    response = await client.post("/auth/register", json=duplicate)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "USER_ALREADY_EXISTS"


async def test_register_duplicate_username_returns_409(client: AsyncClient) -> None:
    payload = await register_user(client, "duplicate_username")
    duplicate = user_payload("other_username")
    duplicate["username"] = payload["username"]

    response = await client.post("/auth/register", json=duplicate)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "USER_ALREADY_EXISTS"


async def test_register_rejects_weak_password_and_invalid_email(client: AsyncClient) -> None:
    weak_password = user_payload("weak")
    weak_password["password"] = "weak"
    invalid_email = user_payload("invalid_email")
    invalid_email["email"] = "not-an-email"

    weak_response = await client.post("/auth/register", json=weak_password)
    invalid_email_response = await client.post("/auth/register", json=invalid_email)

    assert weak_response.status_code == 422
    assert invalid_email_response.status_code == 422
    assert weak_response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_login_success_and_invalid_credentials(client: AsyncClient) -> None:
    payload = await register_user(client, "login")

    success = await client.post(
        "/auth/login",
        json={"email": payload["email"], "password": VALID_PASSWORD},
    )
    missing_email = await client.post(
        "/auth/login",
        json={"email": "missing@example.com", "password": VALID_PASSWORD},
    )
    wrong_password = await client.post(
        "/auth/login",
        json={"email": payload["email"], "password": "WrongPass1!"},
    )

    assert success.status_code == 200
    assert success.json()["access_token"]
    assert success.json()["refresh_token"]
    assert missing_email.status_code == 401
    assert wrong_password.status_code == 401
    assert missing_email.json()["error"]["message"] == "Invalid credentials."
    assert wrong_password.json()["error"]["message"] == "Invalid credentials."


async def test_inactive_user_login_returns_403(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    payload = await register_user(client, "inactive")
    user = await get_user_by_email(db_session, payload["email"])
    user.is_active = False
    await db_session.commit()

    response = await client.post(
        "/auth/login",
        json={"email": payload["email"], "password": VALID_PASSWORD},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INACTIVE_USER"


async def test_refresh_rotates_token_and_rejects_old_token(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    payload = await register_user(client, "refresh")
    tokens = await login_user(client, payload["email"])

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 200
    new_tokens = response.json()
    assert new_tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

    refresh_repo = RefreshTokenRepository(db_session)
    old_token = await refresh_repo.get_by_hash(hash_token(tokens["refresh_token"]))
    assert old_token is not None
    await db_session.refresh(old_token)
    assert old_token.revoked is True

    old_token_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert old_token_response.status_code == 401
    assert old_token_response.json()["error"]["code"] == "TOKEN_REVOKED"


async def test_refresh_reuse_revokes_all_user_tokens(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    payload = await register_user(client, "reuse")
    first_login = await login_user(client, payload["email"])
    second_login = await login_user(client, payload["email"])

    logout_response = await client.post(
        "/auth/logout",
        json={"refresh_token": first_login["refresh_token"]},
    )
    assert logout_response.status_code == 204

    reuse_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": first_login["refresh_token"]},
    )
    assert reuse_response.status_code == 401
    assert reuse_response.json()["error"]["code"] == "TOKEN_REVOKED"

    second_token = await RefreshTokenRepository(db_session).get_by_hash(
        hash_token(second_login["refresh_token"])
    )
    assert second_token is not None
    await db_session.refresh(second_token)
    assert second_token.revoked is True


async def test_refresh_rejects_access_token(client: AsyncClient) -> None:
    payload = await register_user(client, "refresh_access")
    tokens = await login_user(client, payload["email"])

    response = await client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_TOKEN"


async def test_logout_is_idempotent_and_revokes_token(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    payload = await register_user(client, "logout")
    tokens = await login_user(client, payload["email"])

    first = await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    second = await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})

    assert first.status_code == 204
    assert second.status_code == 204
    stored_token = await RefreshTokenRepository(db_session).get_by_hash(
        hash_token(tokens["refresh_token"])
    )
    assert stored_token is not None
    await db_session.refresh(stored_token)
    assert stored_token.revoked is True


async def test_me_requires_access_token_and_returns_user(client: AsyncClient) -> None:
    payload = await register_user(client, "me")
    tokens = await login_user(client, payload["email"])

    missing = await client.get("/auth/me")
    authorized = await client.get("/auth/me", headers=auth_header(tokens["access_token"]))

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "UNAUTHORIZED"
    assert authorized.status_code == 200
    assert authorized.json()["email"] == payload["email"]


async def test_me_rejects_expired_access_token(client: AsyncClient) -> None:
    payload = await register_user(client, "expired")
    user_tokens = await login_user(client, payload["email"])
    decoded_sub = jwt.decode(
        user_tokens["access_token"],
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": False},
    )["sub"]
    expired_access = jwt.encode(
        {
            "sub": decoded_sub,
            "exp": datetime.now(UTC) - timedelta(minutes=1),
            "iat": datetime.now(UTC) - timedelta(minutes=2),
            "type": "access",
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    response = await client.get("/auth/me", headers=auth_header(expired_access))

    assert response.status_code == 401


async def test_patch_me_updates_profile(client: AsyncClient) -> None:
    payload = await register_user(client, "patch")
    tokens = await login_user(client, payload["email"])

    response = await client.patch(
        "/auth/me",
        headers=auth_header(tokens["access_token"]),
        json={"first_name": "Updated"},
    )

    assert response.status_code == 200
    assert response.json()["first_name"] == "Updated"
    assert response.json()["last_name"] == "User"


async def test_logout_all_revokes_all_tokens(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    payload = await register_user(client, "logout_all")
    first_login = await login_user(client, payload["email"])
    second_login = await login_user(client, payload["email"])

    response = await client.post(
        "/auth/logout-all",
        headers=auth_header(first_login["access_token"]),
    )

    assert response.status_code == 200
    assert response.json()["revoked_count"] == 2
    second_token = await RefreshTokenRepository(db_session).get_by_hash(
        hash_token(second_login["refresh_token"])
    )
    assert second_token is not None
    await db_session.refresh(second_token)
    assert second_token.revoked is True


async def test_change_password_revokes_tokens_and_requires_current_password(
    client: AsyncClient,
) -> None:
    payload = await register_user(client, "password")
    tokens = await login_user(client, payload["email"])

    wrong_current = await client.post(
        "/auth/me/password",
        headers=auth_header(tokens["access_token"]),
        json={"current_password": "WrongPass1!", "new_password": "NewStrongPass1!"},
    )
    success = await client.post(
        "/auth/me/password",
        headers=auth_header(tokens["access_token"]),
        json={"current_password": VALID_PASSWORD, "new_password": "NewStrongPass1!"},
    )
    refresh_after_change = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    old_password_login = await client.post(
        "/auth/login",
        json={"email": payload["email"], "password": VALID_PASSWORD},
    )
    new_password_login = await client.post(
        "/auth/login",
        json={"email": payload["email"], "password": "NewStrongPass1!"},
    )

    assert wrong_current.status_code == 401
    assert success.status_code == 204
    assert refresh_after_change.status_code == 401
    assert old_password_login.status_code == 401
    assert new_password_login.status_code == 200


async def test_full_auth_happy_path(client: AsyncClient) -> None:
    payload = await register_user(client, "flow")
    tokens = await login_user(client, payload["email"])

    me = await client.get("/auth/me", headers=auth_header(tokens["access_token"]))
    refreshed = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    refreshed_tokens = refreshed.json()
    me_with_new_access = await client.get(
        "/auth/me",
        headers=auth_header(refreshed_tokens["access_token"]),
    )
    logout = await client.post(
        "/auth/logout",
        json={"refresh_token": refreshed_tokens["refresh_token"]},
    )
    refresh_after_logout = await client.post(
        "/auth/refresh",
        json={"refresh_token": refreshed_tokens["refresh_token"]},
    )

    assert me.status_code == 200
    assert refreshed.status_code == 200
    assert me_with_new_access.status_code == 200
    assert logout.status_code == 204
    assert refresh_after_logout.status_code == 401
