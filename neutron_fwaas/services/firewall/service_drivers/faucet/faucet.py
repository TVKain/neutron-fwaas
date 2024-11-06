import os

import ipaddress

from contextlib import contextmanager
from oslo_config import cfg

from ruamel.yaml import YAML

from pydantic import BaseModel

from neutron_fwaas.temp.log import logger

from neutron_fwaas.services.firewall.service_drivers.faucet.model import acl
from neutron_fwaas.services.firewall.service_drivers.faucet.model import dp
from neutron_fwaas.services.firewall.service_drivers.faucet.model import vlan

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.arp_acl_manager import (
    ArpAclManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.private_acl_manager import (
    PrivateAclManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.datapath.dp_manager import (
    DpManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.vlan.vlan_manager import (
    VlanManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.acl_manager import (
    AclManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet import consts


class FaucetFirewallManager:

    PRIVATE_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def __init__(self):
        self.folder_path = cfg.CONF.faucet.file_path

        self.yaml = YAML()
        self.yaml.indent(mapping=2, sequence=4, offset=2)

        self.dp_id = cfg.CONF.faucet.dp_id

        self.egress_interface = cfg.CONF.faucet.egress_interface
        self.ingress_interface = cfg.CONF.faucet.ingress_interface

        self.interfaces = [self.egress_interface, self.ingress_interface]

        self.dp_manager = DpManager(
            base_path=self.folder_path,
            yaml=self.yaml,
            dp_id=self.dp_id,
            interfaces=self.interfaces,
        )

        self.arp_manager = ArpAclManager(base_path=self.folder_path, yaml=self.yaml)

        self.private_manager = PrivateAclManager(
            base_path=self.folder_path, yaml=self.yaml
        )

    def intialize_main_files(self):
        self.dp_manager.initialize_dp()
        self.arp_manager.initialize_arp_acl()
        self.private_manager.initialize_private_acl()

        self.dp_manager.include_manager.add_include(self.arp_manager.ARP_ACL_FILENAME)
        self.dp_manager.include_manager.add_include(
            self.private_manager.PRIVATE_ACL_FILENAME
        )
        self.dp_manager.interface_manager.add_acl(
            entry_name=self.arp_manager.ARP_ACL_NAME, interface=self.ingress_interface
        )
        self.dp_manager.interface_manager.add_acl(
            entry_name=self.arp_manager.ARP_ACL_NAME, interface=self.egress_interface
        )
        self.dp_manager.interface_manager.add_acl(
            entry_name=self.private_manager.PRIVATE_EGRESS_ACL_NAME,
            interface=self.egress_interface,
        )
        self.dp_manager.interface_manager.add_acl(
            entry_name=self.private_manager.PRIVATE_INGRESS_ACL_NAME,
            interface=self.ingress_interface,
        )

    def add_vlan_acl(self, vlan_id: int):
        """This function add acl file for a VLAN
        Specifically it will
            1. Create a vlan file
            2. Create a vlan acl file
            3. Include the vlan file and vlan acl file in the main Faucet file
            4. Add those into the tagged_vlans and acls_in
                portion of the interfaces in the main Faucet file

        This function assumes that no vlan and vlan acl file exists or we can override it
        Args:
            vlan_id (int): the vlan vid
        """
        vlan_manager = VlanManager(
            base_path=self.folder_path, vlan_id=vlan_id, yaml=self.yaml
        )

        acl_manager = AclManager(
            base_path=self.folder_path,
            vlan_id=vlan_id,
            yaml=self.yaml,
            interfaces=self.interfaces,
        )

        vlan_manager.initialize_vlan()
        acl_manager.initialize_acl()

        self.dp_manager.include_manager.add_include_vlan(vlan_id=vlan_id)
        self.dp_manager.interface_manager.add_vlan_all(vlan_id=vlan_id)

        self.dp_manager.include_manager.add_include_vlan_acl(vlan_id=vlan_id)
        self.dp_manager.interface_manager.add_acl_vlan_all(vlan_id=vlan_id)

    def remove_acl_vlan(self, vlan_id: int):
        """Remove acl file for a vlan

        1. Destroy vlan file
        2. Destroy vlan acl file
        3. Update include for main file to remove related entries

        Args:
            vlan_id (int): the vlan vid
        """
        vlan_manager = VlanManager(
            base_path=self.folder_path, vlan_id=vlan_id, yaml=self.yaml
        )

        acl_manager = AclManager(
            base_path=self.folder_path,
            vlan_id=vlan_id,
            yaml=self.yaml,
            interfaces=self.interfaces,
        )

        vlan_manager.destroy_vlan()
        acl_manager.destroy_acl()

        self.dp_manager.interface_manager.remove_vlan_all(vlan_id=vlan_id)
        self.dp_manager.interface_manager.remove_acl_vlan_all(vlan_id=vlan_id)

        self.dp_manager.include_manager.remove_include_vlan(vlan_id=vlan_id)
        self.dp_manager.include_manager.remove_include_vlan_acl(vlan_id=vlan_id)

    # This will be used for removing ingress/egress policy from firewall group
    # Only called this with firewall groups that contains ports
    def remove_acls_from_vlan(self, vlan_id: int, rules, interface: int):
        acl_manager = AclManager(
            base_path=self.folder_path,
            vlan_id=vlan_id,
            interfaces=self.interfaces,
            yaml=self.yaml,
        )

        faucet_rules = self._convert_ops_rules_to_faucet_rules(
            ops_rules=rules, vlan_id=vlan_id
        )

        for faucet_rule in faucet_rules:
            acl_manager.remove_rule(interface=interface, rule=faucet_rule)

    def remove_acls_from_vlan_egress(self, vlan_id: int, rules):
        self.remove_acls_from_vlan(
            vlan_id=vlan_id, rules=rules, interface=self.egress_interface
        )

    def remove_acls_from_vlan_ingress(self, vlan_id: int, rules):
        self.remove_acls_from_vlan(
            vlan_id=vlan_id, rules=rules, interface=self.ingress_interface
        )

    def add_acls_to_vlan_egress(self, vlan_id: int, rules):
        """
        Assumes the acl vlan is added already
        """

        self.add_acls_to_vlan(
            vlan_id=vlan_id, rules=rules, interface=self.egress_interface
        )

    def add_acls_to_vlan_ingress(self, vlan_id: int, rules):
        """
        Assumes the acl vlan is added already
        """

        self.add_acls_to_vlan(
            vlan_id=vlan_id, rules=rules, interface=self.ingress_interface
        )

    def add_acls_to_vlan(self, vlan_id: int, rules, interface: int):
        """This function adds acl rules for a vlan
        It assumes a vlan file already exists for this vlan entry

        1.

        Args:
            vlan_id (int): _description_
            rules (_type_): _description_
            interface (int): _description_
        """

        acl_manager = AclManager(
            base_path=self.folder_path,
            vlan_id=vlan_id,
            interfaces=self.interfaces,
            yaml=self.yaml,
        )

        faucet_rules = self._convert_ops_rules_to_faucet_rules(
            ops_rules=rules, vlan_id=vlan_id
        )

        logger.info(f"Converted rules {faucet_rules}")

        for index, faucet_rule in enumerate(faucet_rules):
            acl_manager.add_rule(interface=interface, rule=faucet_rule, priority=index)

    def _convert_ops_rules_to_faucet_rules(
        self, ops_rules, vlan_id: int
    ) -> list[acl.Rule]:
        # Disabled rules are ignored
        # Bad rules are also ignored

        rules: list[acl.Rule] = []

        for ops_rule in ops_rules:

            # Skip disabled rules
            if not ops_rule["enabled"]:
                continue

            if self._check_ops_rule(ops_rule=ops_rule, vlan_id=vlan_id):
                rules.append(
                    self._convert_ops_rule_to_faucet_rule(
                        ops_rule=ops_rule, vlan_id=vlan_id
                    )
                )
            else:
                logger.warning(f"Skipping rule {ops_rule["id"]}")

        logger.info(f"Rules after converted {rules}")

        return rules

    def _check_ops_rule(self, ops_rule, vlan_id: int) -> bool:

        if ops_rule["ip_version"] != 4:
            logger.warning(
                f"Adding acl to vlan {vlan_id} failed: IPv6 is not supported"
            )
            return False

        if ops_rule["protocol"]:
            if ops_rule["protocol"] not in consts.ALLOWED_PROTOCOLS:
                logger.warning(
                    f"Adding acl to vlan {vlan_id} failed: Invalid Protocol {ops_rule["protocol"]} specified"
                )
                return False

        if ops_rule["source_ip_address"]:
            try:
                ipaddress.ip_network(ops_rule["source_ip_address"])
            except Exception as e:
                logger.warning(
                    f"Adding acl to vlan {vlan_id} failed: Invalid Source IP Address {ops_rule["source_ip_address"]} specified"
                )
                return False

        if ops_rule["destination_ip_address"]:
            try:
                ipaddress.ip_network(ops_rule["destination_ip_address"])
            except Exception as e:
                logger.warning(
                    f"Adding acl to vlan {vlan_id} failed: Invalid Destination IP Address {ops_rule["destination_ip_address"]} specified"
                )
                return False

        if ops_rule["source_port"]:
            try:
                int(ops_rule["source_port"])
            except Exception as e:
                logger.warning(
                    f"Adding acl to vlan {vlan_id} failed: Invalid Source Port {ops_rule["source_port"]} specified"
                )
                return False

        if ops_rule["destination_port"]:
            try:
                int(ops_rule["destination_port"])
            except Exception as e:
                logger.warning(
                    f"Adding acl to vlan {vlan_id} failed: Invalid Destination Port {ops_rule["destination_port"]} specified"
                )
                return False

        return True

    def _convert_ops_rule_to_faucet_rule(self, ops_rule, vlan_id: int) -> acl.Rule:

        ip_proto = (
            consts.PROTOCOL_NUM_MAP[ops_rule["protocol"]]
            if ops_rule["protocol"]
            else None
        )
        tcp_src = None
        tcp_dst = None
        udp_src = None
        udp_dst = None

        if ops_rule["protocol"] == consts.TCP:

            if ops_rule["source_port"]:
                tcp_src = int(ops_rule["source_port"])

            if ops_rule["destination_port"]:
                tcp_dst = int(ops_rule["destination_port"])

        if ops_rule["protocol"] == consts.UDP:
            if ops_rule["source_port"]:
                udp_src = int(ops_rule["source_port"])

            if ops_rule["destination_port"]:
                udp_dst = int(ops_rule["destination_port"])

        actions = acl.Action(allow=True)

        if ops_rule["action"] == "allow":
            actions = acl.Action(
                ct=acl.Conntrack(
                    zone=AclManager.get_ct_zone(vlan_id=vlan_id),
                    table=consts.TRACKED_TABLE,
                    flags=consts.COMMIT_FLAG,
                )
            )
        else:
            actions = acl.Action(allow=False)

        rule = acl.Rule(
            eth_type=consts.IPV4_ETH_TYPE,
            ip_proto=ip_proto,
            vlan_vid=vlan_id,
            ipv4_src=ops_rule["source_ip_address"],
            ipv4_dst=ops_rule["destination_ip_address"],
            ct_state=consts.NEW_STATE,
            tcp_src=tcp_src,
            tcp_dst=tcp_dst,
            udp_src=udp_src,
            udp_dst=udp_dst,
            actions=actions,
        )

        logger.info(f"Converted ops_rule {ops_rule["id"]} to faucet rule successfully")

        logger.info(f"{rule.model_dump_json()}")

        return rule
