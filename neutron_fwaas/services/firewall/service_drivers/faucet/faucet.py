import os 

from oslo_config import cfg

from ruamel.yaml import YAML

from neutron_fwaas.temp.log import logger

from neutron_fwaas.services.firewall.service_drivers.faucet.config import acl 
from neutron_fwaas.services.firewall.service_drivers.faucet.config import dp 
from neutron_fwaas.services.firewall.service_drivers.faucet.config import vlan

class FaucetFirewallManager: 
    """
    egress: 1
    ingress: 2
    """
    
    MAIN_FILENAME = "main.yaml"
    
    ARP_ACL_FILENAME = "arp.yaml"
    ARP_ACL_NAME = "allow_arp"
    
    DP_NAME = "br_f"
    HARDWARE = "Open vSwitch"
    
    def __init__(self): 
        self.folder_path = cfg.CONF.faucet.file_path
        
        self.main_file_path = os.path.join(self.folder_path, self.MAIN_FILENAME)
        self.arp_file_path = os.path.join(self.folder_path, self.ARP_ACL_FILENAME)
        
        self.dp_id = cfg.CONF.faucet.dp_id
        self.egress_interface = cfg.CONF.faucet.egress_interface
        self.ingress_interface = cfg.CONF.faucet.ingress_interface
        
        self.yaml = YAML() 
        self.yaml.indent(mapping=2, sequence=4, offset=2) 

    def _add_default_rule(port_id): 
        pass 
    
    def intialize_main_files(self): 
        self._initialize_main_file()
        self._initialize_arp_acl_file()
        
        self._add_vlan_file(400)
        self._add_vlan_file(500)    
        self._add_vlan_to_interface(500)

    def _initialize_arp_acl_file(self): 

        rule = acl.AclRule(
            rule=acl.Rule(
                eth_type="0x0806", 
                action=acl.Action(allow=True)
            )
        ) 
        
        acls = acl.Acls(
            acls=
            {
               self.ARP_ACL_NAME: [rule]    
            }
        )
        
        with open(self.arp_file_path, "w") as file:
            self.yaml.dump(acls.model_dump(exclude_none=True), file)

    def _initialize_main_file(self):
        
        datapath = dp.DP(
            dp_id=self.dp_id, 
            hardware=self.HARDWARE,
            interfaces={
                self.egress_interface: dp.Interface(
                    name="egress_interface"    
                ), 
                self.ingress_interface: dp.Interface(
                    name="ingress_interface"
                ), 
            }
        )
        
        datapaths = dp.DPS(
            dps={
                self.DP_NAME: datapath
            }
        )
        
        try: 
            with open(self.main_file_path, "w") as file:
                self.yaml.dump(datapaths.model_dump(exclude_none=True), file)
        except Exception as e:
            logger.info(e)
    
    
    def _add_vlan_include(self, vlan_id): 
        with open(self.main_file_path, "r") as file: 
            main = self.yaml.load(file) 
            
            datapath: dp.DPS = dp.DPS.model_validate(main)
            
        if not datapath.includes: 
            datapath.includes = [] 
            
        datapath.includes.append(self._get_vlan_filename(vlan_id))
        
        with open(self.main_file_path, "w") as file: 
            self.yaml.dump(datapath.model_dump(exclude_none=True), file)
    
    def _add_vlan_to_interface(self, vlan_id): 
        with open(self.main_file_path, "r") as file: 
            main = self.yaml.load(file)
            
            datapath: dp.DPS = dp.DPS.model_validate(main)
        
        if not datapath.dps[self.DP_NAME].interfaces[self.egress_interface].tagged_vlans:
                datapath.dps[self.DP_NAME].interfaces[self.egress_interface].tagged_vlans = []
            
        datapath.dps[self.DP_NAME].interfaces[self.egress_interface].tagged_vlans.append(
            self._get_vlan_entry_name(vlan_id)
        )
        
        if not datapath.dps[self.DP_NAME].interfaces[self.ingress_interface].tagged_vlans:
                datapath.dps[self.DP_NAME].interfaces[self.ingress_interface].tagged_vlans = []
        
        datapath.dps[self.DP_NAME].interfaces[self.ingress_interface].tagged_vlans.append(
            self._get_vlan_entry_name(vlan_id)
        )
        
        with open(self.main_file_path, "w") as file: 
            self.yaml.dump(datapath.model_dump(exclude_none=True), file)
        
    def _add_vlan_file(self, vlan_id): 
        vlan_filename = os.path.join(self.folder_path, self._get_vlan_filename(vlan_id))
        
        vlan_entry = vlan.VLAN(
            vid=vlan_id
        )
        
        vlans = vlan.VLANS(
            vlans = {
                self._get_vlan_entry_name(vlan_id): vlan_entry
            }
        )
        
        with open(vlan_filename, "w") as file:
            self.yaml.dump(vlans.model_dump(), file)
            
        self._add_vlan_include(vlan_id)
    
    def _add_acl_vlan(self, acl, vlan_id): 
        pass 
    
    def _get_acl_mock_rule(self) -> acl.AclRule: 
        pass 
    
    def _get_vlan_acl_ingress_entry_name(self, vlan_id): 
        return f"ingress_vlan_${vlan_id}"
    
    def _get_vlan_acl_egress_entry_name(self, vlan_id): 
        return f"egress_vlan_${vlan_id}"
    
    def _get_vlan_acl_filename(self, vlan_id): 
        return f"vlan_{vlan_id}.acl.yaml"
    
    def _get_vlan_filename(self, vlan_id): 
        return f"vlan_{vlan_id}.yaml"
    
    def _get_vlan_entry_name(self, vlan_id): 
        return f"vlan_{vlan_id}"