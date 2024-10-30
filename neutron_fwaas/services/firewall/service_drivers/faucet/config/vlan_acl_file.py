from pydantic import BaseModel

from neutron_fwaas.services.firewall.service_drivers.faucet.config.acl import AclRule
from neutron_fwaas.services.firewall.service_drivers.faucet.config.vlan import VLAN

class VlanAclFile(BaseModel): 
    vlans: dict[str, VLAN]
    acls: dict[str, list[AclRule]]