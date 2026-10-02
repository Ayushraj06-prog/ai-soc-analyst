from fastapi import HTTPException


def api_error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"code": code, "message": message})
