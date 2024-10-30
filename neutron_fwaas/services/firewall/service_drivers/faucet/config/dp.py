from pydantic import BaseModel

from typing import Literal, Optional

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
    dps: dict[str, DP]
    
