from typing import Optional, List

from pydantic import BaseModel, ValidationError
from starlette import status

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    status: str = 'user'


class UserInDB(User):
    hashed_password: str