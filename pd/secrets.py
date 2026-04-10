from typing import Optional

from pydantic.v1 import BaseModel, validator, constr


class SecretList(BaseModel):
    name: str
    secret_name: Optional[str] = None

    @validator('secret_name', always=True)
    def set_secret_name(cls, value, values):
        return '{{secret.%s}}' % values['name']


class SecretCreate(BaseModel):
    name: constr(regex='^[A-Za-z0-9_]*$', min_length=1)
    value: Optional[str] = None

    @validator('name')
    def name_must_not_start_or_end_with_dash(cls, v):
        if v[0] == '-' or v[-1] == '-':
            raise ValueError('name must not start or end with a dash')
        return v


class SecretUpdate(SecretCreate):
    ...


class SecretDetail(SecretList):
    is_hidden: Optional[bool] = False
    value: Optional[str] = None
