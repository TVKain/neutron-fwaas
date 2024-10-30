from typing import Optional

from pydantic import BaseModel

class Conntrack(BaseModel): 
    zone: Optional[int]
    table: Optional[int] 
    flags: Optional[int]

class Action(BaseModel): 
    allow: bool 
    ct: Optional[Conntrack] = None

class Rule(BaseModel): 
    eth_type: str 
    vlan_vid: Optional[int] = None
    ct_state: Optional[str] = None
    ct_zone: Optional[int] = None 
    action: Action 

class AclRule(BaseModel): 
    rule: Rule 

class Acls(BaseModel): 
    acls: dict[str, list[AclRule]]


