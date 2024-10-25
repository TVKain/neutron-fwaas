from pydantic import BaseModel

class Rule(BaseModel): 
    eth_type: str 
    vlan_vid: int 
    ct_state: str 
    ct_zone: int 
    