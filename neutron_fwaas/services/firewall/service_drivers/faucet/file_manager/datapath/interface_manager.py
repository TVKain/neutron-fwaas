from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.vlan.vlan_manager import (
    VlanManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.acl_manager import (
    AclManager,
)

from neutron_fwaas.temp.log import logger


class InterfaceManager:

    def __init__(
        self,
        dp_file_ctx: YAMLManager,
        interfaces: list[int],
        dp_name: str,
    ):
        self._dp_file_ctx = dp_file_ctx
        self._interfaces = interfaces
        self._dp_name = dp_name

    def add_acl(self, entry_name: str, interface: int):
        with self._dp_file_ctx as datapaths:
            if not datapaths.dps[self._dp_name].interfaces[interface]:
                LOG.warning(
                    f"""Can not add {entry_name} to interface '{interface}': 
                    interface '{interface}' does not exist on {self._dp_name}"""
                )
                return

            if not datapaths.dps[self._dp_name].interfaces[interface].acls_in:
                datapaths.dps[self._dp_name].interfaces[interface].acls_in = []

            if (
                entry_name
                not in datapaths.dps[self._dp_name].interfaces[interface].acls_in
            ):
                datapaths.dps[self._dp_name].interfaces[interface].acls_in.append(
                    entry_name
                )

    def add_acl_vlan(self, vlan_id: int, interface: int):
        entry_name = AclManager.get_vlan_acl_entry_name(
            vlan_id=vlan_id, interface=interface
        )

        self.add_acl(entry_name=entry_name, interface=interface)

    def add_acl_vlan_all(self, vlan_id: int):
        for interface in self._interfaces:
            self.add_acl_vlan(vlan_id=vlan_id, interface=interface)

    def remove_acl(self, entry_name: str, interface: int):
        with self._dp_file_ctx as datapaths:

            if datapaths.dps[self._dp_name].interfaces[interface].acls_in:
                try:
                    datapaths.dps[self._dp_name].interfaces[interface].acls_in.remove(
                        entry_name
                    )

                    if (
                        len(datapaths.dps[self._dp_name].interfaces[interface].acls_in)
                        == 0
                    ):
                        datapaths.dps[self._dp_name].interfaces[
                            interface
                        ].acls_in = None

                except Exception as e:
                    logger.warning(f"Delete acl {entry_name} failed: {e}")
            else:
                logger.warning(f"Delete acl {entry_name} failed: acls_in is empty")

    def remove_acl_vlan(self, vlan_id: int, interface: int):
        acl_vlan_entry_name = AclManager.get_vlan_acl_entry_name(
            vlan_id=vlan_id, interface=interface
        )

        self.remove_acl(entry_name=acl_vlan_entry_name, interface=interface)

    def remove_acl_vlan_all(self, vlan_id: int):
        for interface in self._interfaces:
            self.remove_acl_vlan(vlan_id=vlan_id, interface=interface)

    def add_vlan(self, vlan_id: int, interface: int):
        with self._dp_file_ctx as datapaths:
            vlan_entry_name = VlanManager.get_vlan_entry_name(vlan_id)

            if not datapaths.dps[self._dp_name].interfaces[interface].tagged_vlans:
                datapaths.dps[self._dp_name].interfaces[interface].tagged_vlans = []

            if (
                vlan_entry_name
                not in datapaths.dps[self._dp_name].interfaces[interface].tagged_vlans
            ):
                datapaths.dps[self._dp_name].interfaces[interface].tagged_vlans.append(
                    vlan_entry_name
                )

    def add_vlan_all(self, vlan_id: int):
        for interface in self._interfaces:
            self.add_vlan(vlan_id=vlan_id, interface=interface)

    def remove_vlan(self, vlan_id: int, interface: int):
        with self._dp_file_ctx as datapaths:
            vlan_entry_name = VlanManager.get_vlan_entry_name(vlan_id)

            if datapaths.dps[self._dp_name].interfaces[interface].tagged_vlans:
                try:
                    datapaths.dps[self._dp_name].interfaces[
                        interface
                    ].tagged_vlans.remove(vlan_entry_name)

                    if (
                        len(
                            datapaths.dps[self._dp_name]
                            .interfaces[interface]
                            .tagged_vlans
                        )
                        == 0
                    ):
                        datapaths.dps[self._dp_name].interfaces[
                            interface
                        ].tagged_vlans = None

                except Exception as e:
                    logger.warning(f"Delete vlan {vlan_id} failed: {e}")
            else:
                logger.warning(f"Delete vlan {vlan_id} failed: tagged_vlans is empty")

    def remove_vlan_all(self, vlan_id: int):
        for interface in self._interfaces:
            self.remove_vlan(vlan_id=vlan_id, interface=interface)
