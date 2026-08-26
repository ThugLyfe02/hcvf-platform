from __future__ import annotations

from fastapi import HTTPException, status


def api_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def bad_request(code: str, message: str) -> HTTPException:
    return api_error(status.HTTP_400_BAD_REQUEST, code, message)


def unauthorized(message: str = "A valid API key is required.") -> HTTPException:
    return api_error(status.HTTP_401_UNAUTHORIZED, "unauthorized", message)


def not_found(resource: str) -> HTTPException:
    return api_error(
        status.HTTP_404_NOT_FOUND,
        f"{resource}_not_found",
        f"The requested {resource} was not found.",
    )


def conflict(code: str, message: str) -> HTTPException:
    return api_error(status.HTTP_409_CONFLICT, code, message)


def service_unavailable(code: str, message: str) -> HTTPException:
    return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, code, message)
