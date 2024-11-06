import os
from oslo_config import cfg

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.yaml_manager import (
    YAMLManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.arp_acl_manager import (
    ArpAclManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.acl.private_acl_manager import (
    PrivateAclManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.datapath.include_manager import (
    IncludeManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.file_manager.datapath.interface_manager import (
    InterfaceManager,
)

from neutron_fwaas.services.firewall.service_drivers.faucet.model import dp

from neutron_fwaas.temp.log import logger

LOG = logger


class DpManager:
    _DP_FILENAME = "dp.yaml"
    _DP_NAME = "br_f"
    _HARDWARE = "Open vSwitch"

    def __init__(self, base_path: str, dp_id: int, interfaces: list[int], yaml):
        self._dp_id = dp_id

        self.base_path = base_path
        self.yaml = yaml

        self.interfaces = interfaces

        self._dp_file_ctx = YAMLManager(
            file_path=os.path.join(self.base_path, self._DP_FILENAME),
            pydantic_class=dp.DPS,
            yaml=self.yaml,
        )

        self.interface_manager = InterfaceManager(
            dp_file_ctx=self._dp_file_ctx,
            interfaces=self.interfaces,
            dp_name=self._DP_NAME,
        )
        self.include_manager = IncludeManager(dp_file_ctx=self._dp_file_ctx)

    def initialize_dp(self):
        # arp_manager = ArpAclManager(base_path=self.base_path, yaml=self.yaml)

        # private_manager = PrivateAclManager(base_path=self.base_path, yaml=self.yaml)

        interfaces = {}

        for interface in self.interfaces:
            interfaces[interface] = dp.Interface(name=f"interface_{interface}")

        datapath = dp.DP(
            dp_id=self._dp_id, hardware=self._HARDWARE, interfaces=interfaces
        )

        with self._dp_file_ctx as datapaths:
            datapaths.dps = {self._DP_NAME: datapath}

        # self.include_manager.add_include(arp_manager.ARP_ACL_FILENAME)

        # for interface in self.interfaces:
        #     self.interface_manager.add_acl(
        #         entry_name=arp_manager.ARP_ACL_NAME, interface=interface
        #     )
