import os

from neutron_fwaas.services.firewall.service_drivers.faucet.model import vlan

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.temp.log import logger


class VlanManager:
    def __init__(self, base_path: str, vlan_id: int, yaml):
        self.vlan_id = vlan_id
        self.yaml = yaml
        self.base_path = base_path

    def _vlan_file_ctx(self):
        return YAMLManager(
            file_path=os.path.join(
                self.base_path, self.get_vlan_filename(vlan_id=self.vlan_id)
            ),
            pydantic_class=vlan.Vlans,
            yaml=self.yaml,
        )

    def destroy_vlan(self):
        self._vlan_file_ctx().delete_yaml()

    def initialize_vlan(self):

        with self._vlan_file_ctx() as vlans:
            vlan_entry = vlan.Vlan(vid=self.vlan_id)

            vlans.vlans = {self.get_vlan_entry_name(vlan_id=self.vlan_id): vlan_entry}

    @staticmethod
    def get_vlan_filename(vlan_id: int) -> str:
        return f"vlan_{vlan_id}.yaml"

    @staticmethod
    def get_vlan_entry_name(vlan_id: int) -> str:
        return f"vlan_{vlan_id}"
