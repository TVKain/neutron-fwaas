from typing import Optional

from pydantic import BaseModel


class Interface(BaseModel):
    name: str
    tagged_vlans: Optional[list[str]] = None
    acls_in: Optional[list[str]] = None


class DP(BaseModel):
    dp_id: int
    hardware: str
    interfaces: dict[int, Interface]


class DPS(BaseModel):
    includes: Optional[list[str]] = None
    dps: Optional[dict[str, DP]] = None
