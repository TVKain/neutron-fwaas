import os

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.model import acl

from neutron_fwaas.services.firewall.service_drivers.faucet import consts

from neutron_fwaas.temp.log import logger


class ArpAclManager:
    ARP_ACL_FILENAME = "arp.yaml"
    ARP_ACL_NAME = "allow_arp"

    def __init__(self, base_path: str, yaml):
        self.base_path = base_path
        self.yaml = yaml

        self._arp_file_ctx = YAMLManager(
            file_path=os.path.join(self.base_path, self.ARP_ACL_FILENAME),
            pydantic_class=acl.Acls,
            yaml=self.yaml,
        )

    def initialize_arp_acl(self):
        with self._arp_file_ctx as acls:
            rule = acl.AclRule(
                rule=acl.Rule(
                    eth_type=consts.ARP_ETH_TYPE, actions=acl.Action(allow=True)
                )
            )

            acls.acls = {self.ARP_ACL_NAME: [rule]}
