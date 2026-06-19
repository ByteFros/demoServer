import pytest

from app.auth.exceptions import InvalidTokenError
from app.core.security import create_access_token, decode_token, hash_password, verify_password


def test_verify_password_accepts_matching_hash() -> None:
    plain_password = "StrongPass1!"
    password_hash = hash_password(plain_password)

    assert verify_password(plain_password, password_hash) is True


def test_access_token_round_trip_preserves_subject() -> None:
    subject = "user-123"
    token = create_access_token(subject)

    claims = decode_token(token)

    assert claims["sub"] == subject
    assert claims["type"] == "access"


def test_decode_token_rejects_corrupted_signature() -> None:
    token = create_access_token("user-123")
    corrupted_token = f"{token[:-1]}x"

    with pytest.raises(InvalidTokenError):
        decode_token(corrupted_token)
