from typing import Optional

from pydantic import BaseModel


class Vlan(BaseModel):
    vid: int


class Vlans(BaseModel):
    vlans: Optional[dict[str, Vlan]] = None
