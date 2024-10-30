from pydantic import BaseModel

class VLAN(BaseModel): 
    vid: int 
    
class VLANS(BaseModel): 
    vlans: dict[str, VLAN] 

