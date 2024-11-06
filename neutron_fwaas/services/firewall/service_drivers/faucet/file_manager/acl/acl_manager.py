import os

from neutron_fwaas.services.firewall.service_drivers.faucet.model import acl

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.model import acl

from neutron_fwaas.services.firewall.service_drivers.faucet import consts


from neutron_fwaas.temp.log import logger


class AclManager:
    # ACL file structure
    # There are always 3 default rules exist in each rule entry
    # - untracked rule
    # - est rule
    # - drop rule
    # rule:                                 index           priority (array index, the lower the better)
    #   - untracked rule                    0               -1
    #   - est rule                          1               0
    #   ...                                 2               1
    #   ... customer's rules (new rules)    3               2
    #   ...                                 4               3
    #   - drop rule                         n               n - 1

    # Faucet determines the priority implicitly based on the index of the rules in the array the higher the lower priority

    # Add one rule
    # current rule list contains n entries
    #
    # rulelists = [rule1, rule2, rule3, rule4, ....]
    #
    # rulelists.insert(priority + 1, rule)
    # This will make the rules in faucet consistent with the priority in neutron fwaas

    # Remove one rule
    # This should be easy because we're using remove method which should shift the array accordingly

    def __init__(self, base_path: str, vlan_id: int, interfaces: list[int], yaml):
        self.vlan_id = vlan_id
        self.yaml = yaml
        self.base_path = base_path

        self._interfaces = interfaces

        self._acl_file_ctx = YAMLManager(
            file_path=os.path.join(
                self.base_path, self.get_vlan_acl_filename(self.vlan_id)
            ),
            pydantic_class=acl.Acls,
            yaml=self.yaml,
        )

    def initialize_acl(self):
        with self._acl_file_ctx as acls:
            drop_rule = self._default_drop_rule()
            untracked_rule = self._default_untracked_rule()
            established_rule = self._default_established_rule()

            acls.acls = {}

            for interface in self._interfaces:

                acls.acls[self.get_vlan_acl_entry_name(self.vlan_id, interface)] = [
                    untracked_rule,
                    established_rule,
                    drop_rule,
                ]

    def destroy_acl(self):
        self._acl_file_ctx.delete_yaml()

    def _default_drop_rule(self) -> acl.AclRule:
        rule = acl.AclRule(
            rule=acl.Rule(vlan_vid=self.vlan_id, actions=acl.Action(allow=False))
        )
        return rule

    def _default_untracked_rule(self) -> acl.AclRule:
        rule = acl.AclRule(
            rule=acl.Rule(
                eth_type=consts.IPV4_ETH_TYPE,
                vlan_vid=self.vlan_id,
                ct_state=consts.UNTRACKED_STATE,
                actions=acl.Action(
                    ct=acl.Conntrack(zone=AclManager.get_ct_zone(self.vlan_id))
                ),
            )
        )
        return rule

    def _default_established_rule(self) -> acl.AclRule:
        rule = acl.AclRule(
            rule=acl.Rule(
                eth_type=consts.IPV4_ETH_TYPE,
                vlan_vid=self.vlan_id,
                ct_state=consts.ESTABLISHED_STATE,
                ct_zone=AclManager.get_ct_zone(self.vlan_id),
                actions=acl.Action(allow=True),
            )
        )

        return rule

    """
    allow_egress_tenant_vlan300:
  - rule:
      eth_type: "0x0800"
      vlan_vid: 300
      ct_state: 0/0x20
      actions:
        ct:
          zone: 0
          table: 0
    """

    def add_rule(self, interface: int, rule: acl.Rule, priority: int):
        """This function add one acl rule for a vlan on a specified interface

        The priority is mapped to an index in the acl rules array

        Args:
            interface (int): interface number
            rule (acl.Rule): rule
            priority (int): priority

        Raises:
            FileNotFoundError: _description_
            ValueError: _description_
        """

        try:
            with self._acl_file_ctx as acls:
                if not acls.acls:
                    raise FileNotFoundError(f"ACL file does not exist")

                if rule in acls.acls:
                    raise ValueError(f"Duplicate rule exists")

                acls.acls[
                    AclManager.get_vlan_acl_entry_name(self.vlan_id, interface)
                ].insert(priority + 1, acl.AclRule(rule=rule))
        except Exception as e:
            logger.warning(
                f"Adding rule for vlan {self.vlan_id} on interface {interface} failed: {e}"
            )

    def remove_rule(self, interface: int, rule: acl.Rule):
        """This function remove acl rule for a vlan on a specified interface

        Args:
            interface (int): _description_
            rule (acl.Rule): _description_
        """
        try:
            with self._acl_file_ctx as acls:

                try:
                    acls.acls[
                        AclManager.get_vlan_acl_entry_name(self.vlan_id, interface)
                    ].remove(rule)
                except ValueError as e:
                    raise ValueError("No such rule exist")
        except Exception as e:
            logger.error(
                f"Removing rule {rule} from f{interface} f{self.vlan_id} failed: {e}"
            )

    @staticmethod
    def get_ct_zone(vlan_id: int) -> int:
        return vlan_id + consts.CT_ZONE_OFFSET

    @staticmethod
    def get_vlan_acl_filename(vlan_id: int) -> str:
        return f"vlan_{vlan_id}.acl.yaml"

    @staticmethod
    def get_vlan_acl_entry_name(vlan_id: int, interface: int) -> str:
        return f"{interface}_vlan_{vlan_id}"
