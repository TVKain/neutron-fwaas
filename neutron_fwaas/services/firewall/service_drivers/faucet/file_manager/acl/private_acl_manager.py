import os

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.model import acl

from neutron_fwaas.services.firewall.service_drivers.faucet import consts

from neutron_fwaas.temp.log import logger


class PrivateAclManager:
    PRIVATE_ACL_FILENAME = "private.yaml"
    PRIVATE_INGRESS_ACL_NAME = "allow_ingress_private"
    PRIVATE_EGRESS_ACL_NAME = "allow_egress_private"

    def __init__(self, base_path: str, yaml):
        self.base_path = base_path
        self.yaml = yaml

        self._private_file_ctx = YAMLManager(
            file_path=os.path.join(
                self.base_path, PrivateAclManager.PRIVATE_ACL_FILENAME
            ),
            pydantic_class=acl.Acls,
            yaml=self.yaml,
        )

    def initialize_private_acl(self):
        with self._private_file_ctx as acls:

            acls.acls = {
                PrivateAclManager.PRIVATE_INGRESS_ACL_NAME: self._private_ingress_default_rules(),
                PrivateAclManager.PRIVATE_EGRESS_ACL_NAME: self._private_egress_default_rules(),
            }

    def _private_egress_default_rules(self) -> list[acl.AclRule]:
        rules = []
        for subnet in consts.PRIVATE_SUBNETS:
            rules.append(
                acl.AclRule(
                    rule=acl.Rule(
                        eth_type=consts.IPV4_ETH_TYPE,
                        ipv4_dst=subnet,
                        actions=acl.Action(allow=True),
                    )
                )
            )
        return rules

    def _private_ingress_default_rules(self) -> list[acl.AclRule]:
        rules = []
        for subnet in consts.PRIVATE_SUBNETS:
            rules.append(
                acl.AclRule(
                    rule=acl.Rule(
                        eth_type=consts.IPV4_ETH_TYPE,
                        ipv4_src=subnet,
                        actions=acl.Action(allow=True),
                    )
                )
            )
        return rules
