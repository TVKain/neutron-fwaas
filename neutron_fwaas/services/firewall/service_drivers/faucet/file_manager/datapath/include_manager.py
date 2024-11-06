from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.vlan.vlan_manager import (
    VlanManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.acl_manager import (
    AclManager,
)


from neutron_fwaas.temp.log import logger


class IncludeManager:
    def __init__(self, dp_file_ctx):
        self._dp_file_ctx = dp_file_ctx

    def add_include(self, file_path: str):
        with self._dp_file_ctx as datapath:
            if not datapath.includes:
                datapath.includes = []

            if file_path not in datapath.includes:
                datapath.includes.append(file_path)

    def add_include_vlan(self, vlan_id: int):
        self.add_include(file_path=VlanManager.get_vlan_filename(vlan_id=vlan_id))

    def add_include_vlan_acl(self, vlan_id: int):
        self.add_include(file_path=AclManager.get_vlan_acl_filename(vlan_id=vlan_id))

    def remove_include(self, file_path: str):
        with self._dp_file_ctx as datapath:
            if datapath.includes:
                try:
                    datapath.includes.remove(file_path)
                except Exception as e:
                    logger.warning(f"Remove include {file_path} failed: {e}")
            else:
                logger.warning(f"Remove include {file_path} failed: include is empty")

    def remove_include_vlan(self, vlan_id: int):
        self.remove_include(file_path=VlanManager.get_vlan_filename(vlan_id=vlan_id))

    def remove_include_vlan_acl(self, vlan_id: int):
        self.remove_include(file_path=AclManager.get_vlan_acl_filename(vlan_id=vlan_id))
