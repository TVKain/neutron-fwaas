# Copyright 2024 FPT Smart Cloud, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This firewall driver for the Faucet controller
# This firewall driver has limited capabilities and is only intended for private vlan network and public vlan network

# Limitations
# - Only works with centralized router
# - Only works with vlan based networks (VXLAN, GENEVE is not supported)
# - OpenStack deployments must contain 2 provider vlan type networks
#   (2 external interfaces - 1 for public vlan, 1 for private vlan)

# This will work along side an OpenStack ML2/OVN deployments, ML2/OVS has not been tested
# The point of which ACL is applied is the internal port (private port) of the router
# We assume that the internal port of the router is connected to a VLAN typed network other network types will be ignored

#                      |                                                  ACL HERE          |
#                      |                                                      |             |
#                      |                               |--------|             |             |
# external vlan network|-----(external-port)-----------| Router |-----(internal port)-------|internal vlan network
#                      |                               |--------|                           |
#                      |                                                                    |
#                      |                                                                    |


import traceback

import logging

from oslo_config import cfg

from neutron_lib import context as lib_context

from neutron_lib import constants as const

from neutron_fwaas.services.firewall.service_drivers import driver_api


from neutron_fwaas.services.firewall.service_drivers.faucet.faucet import (
    FaucetFirewallManager,
)

from neutron_fwaas.temp.log import logger

LOG = logging.getLogger(__name__)


class FaucetFwaasDriver(driver_api.FirewallDriverDB):
    def __init__(self, service_plugin):
        super(FaucetFwaasDriver, self).__init__(service_plugin)

        self._mech = None

        self.faucet = FaucetFirewallManager()

        self._resync_config(context=lib_context.get_admin_context())

    def is_supported_l2_port(self, port):
        return False

    def is_supported_l3_port(self, port):
        return True

    def start_rpc_listener(self):
        return []

    def create_firewall_group_precommit(self, context, firewall_group):
        if not firewall_group["ports"]:
            LOG.info(
                "No ports bound to firewall_group: %s, " "setting this to inactive",
                firewall_group["id"],
            )
            status = const.INACTIVE
        else:
            status = const.PENDING_CREATE
        firewall_group["status"] = status

    def create_firewall_group_postcommit(self, context, firewall_group):
        try:
            if (
                firewall_group["ingress_firewall_policy_id"]
                or firewall_group["egress_firewall_policy_id"]
            ):
                LOG.info("khanhtv28 contains ingress or egress firewall policy")
            if firewall_group["ports"]:
                firewall_group["status"] = const.ACTIVE
                LOG.info("khanhtv28 firewall contains port")

                self._apply_firewall_group_to_ports(
                    context=context,
                    port_ids=firewall_group["ports"],
                    firewall_group_id=firewall_group["id"],
                )
        except Exception:
            LOG.error("Failed to create_firewall_group_postcommit.")
            raise
        else:
            self.firewall_db.update_firewall_group_status(
                context, firewall_group["id"], firewall_group["status"]
            )

    def update_firewall_group_precommit(
        self, context, old_firewall_group, new_firewall_group
    ):
        port_updated = set(new_firewall_group["ports"]) != set(
            old_firewall_group["ports"]
        )
        policies_updated = (
            new_firewall_group["ingress_firewall_policy_id"]
            != old_firewall_group["ingress_firewall_policy_id"]
            or new_firewall_group["egress_firewall_policy_id"]
            != old_firewall_group["egress_firewall_policy_id"]
        )
        if port_updated or policies_updated:
            new_firewall_group["status"] = const.PENDING_UPDATE

    def update_firewall_group_postcommit(
        self, context, old_firewall_group, new_firewall_group
    ):
        if new_firewall_group["status"] != const.PENDING_UPDATE:
            return
        old_ports = set(old_firewall_group["ports"])
        new_ports = set(new_firewall_group["ports"])
        old_ing_policy = old_firewall_group["ingress_firewall_policy_id"]
        new_ing_policy = new_firewall_group["ingress_firewall_policy_id"]
        old_eg_policy = old_firewall_group["egress_firewall_policy_id"]
        new_eg_policy = new_firewall_group["egress_firewall_policy_id"]

        removed_ports = old_ports - new_ports
        added_ports = new_ports - old_ports

        # Remove firewall group for all removed ports
        self._remove_firewall_group_from_ports(context=context, port_ids=removed_ports)

        # Apply firewall group to all new ports
        # This includes the old ports that are still present as well
        self._apply_firewall_group_to_ports(
            context=context,
            port_ids=new_ports,
            firewall_group_id=new_firewall_group["id"],
        )

        # If there's no ports we'll just set it inactive
        if not new_ports:
            LOG.info(
                "No ports bound to firewall_group: %s, " "set it to inactive",
                new_firewall_group["id"],
            )
            new_firewall_group["status"] = const.INACTIVE

        if new_ports:
            new_firewall_group["status"] = const.ACTIVE

        logger.info(
            f"FWG with rules: {self.firewall_db.make_firewall_group_dict_with_rules(
            context=context, firewall_group_id=new_firewall_group["id"]
        )}"
        )

        self.firewall_db.update_firewall_group_status(
            context, new_firewall_group["id"], new_firewall_group["status"]
        )

    def update_firewall_policy_postcommit(
        self, context, old_firewall_policy, new_firewall_policy
    ):
        old_rules = old_firewall_policy["firewall_rules"]
        new_rules = new_firewall_policy["firewall_rules"]
        if old_rules == new_rules:
            return

        ingress_fwg_ids, egress_fwg_ids = self.firewall_db.get_fwgs_with_policy(
            context=context, fwp_id=policy_id
        )

        for ingress_fwg_id in ingress_fwg_ids:
            ingress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=ingress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=ingress_fwg_ports,
                firewall_group_id=ingress_fwg_id,
            )
        for egress_fwg_id in egress_fwg_ids:
            egress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=egress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=egress_fwg_ports,
                firewall_group_id=egress_fwg_id,
            )

    def update_firewall_rule_precommit(
        self, context, old_firewall_rule, new_firewall_rule
    ):
        raise NotImplementedError

    def update_firewall_rule_postcommit(
        self, context, old_firewall_rule, new_firewall_rule
    ):
        raise NotImplementedError

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        # A new rule is inserted into a policy we need to
        # 1. Get all firewall groups that uses that policy Either ingress or egress
        # 2. For each firewall group we will do the following steps
        #       2.1 Get all router ports associate with that firewall group
        #       2.2 For each port we will do the following
        #           3.1 Get the vlan
        #           3.2 Use faucet to add acl to that vlan
        # TODO Improve this later

        ingress_fwg_ids, egress_fwg_ids = self.firewall_db.get_fwgs_with_policy(
            context=context, fwp_id=policy_id
        )

        for ingress_fwg_id in ingress_fwg_ids:
            ingress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=ingress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=ingress_fwg_ports,
                firewall_group_id=ingress_fwg_id,
            )
        for egress_fwg_id in egress_fwg_ids:
            egress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=egress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=egress_fwg_ports,
                firewall_group_id=egress_fwg_id,
            )

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        ingress_fwg_ids, egress_fwg_ids = self.firewall_db.get_fwgs_with_policy(
            context=context, fwp_id=policy_id
        )

        for ingress_fwg_id in ingress_fwg_ids:
            ingress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=ingress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=ingress_fwg_ports,
                firewall_group_id=ingress_fwg_id,
            )
        for egress_fwg_id in egress_fwg_ids:
            egress_fwg_ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=egress_fwg_id
            )

            self._apply_firewall_group_to_ports(
                context=context,
                port_ids=egress_fwg_ports,
                firewall_group_id=egress_fwg_id,
            )

    def _get_network_segment_from_port(self, context, port_id: str):

        port_db = self._core_plugin.get_port(context, port_id)

        return self._core_plugin.get_network_segment_by_network_id(
            context, port_db["network_id"]
        )

    def _apply_firewall_group_to_ports(
        self, context, port_ids: list[str], firewall_group_id: str
    ):

        for port_id in port_ids:
            try:
                self._apply_firewall_group_to_port(
                    context=context,
                    port_id=port_id,
                    firewall_group_id=firewall_group_id,
                )
            except Exception as e:
                logger.warning(f"Apply firewall for port {port_id} failed: {e}")
                stack_trace = "".join(
                    traceback.format_exception(type(e), e, e.__traceback__)
                )
                logger.warning(stack_trace)

    def _apply_firewall_group_to_port(
        self, context, port_id: str, firewall_group_id: str
    ):
        """
        Assumes that no acl vlan exist for this port or we can override it
        """

        network_segment = self._get_network_segment_from_port(
            context=context, port_id=port_id
        )

        if network_segment.network_type != "vlan":
            logger.warning(
                f"Network type for port {port_id} is {network_segment.type}, firewall group will be ignored"
            )
            return

        vlan = network_segment.segmentation_id

        self.faucet.add_vlan_acl(vlan_id=vlan)

        firewall_group_with_rules = (
            self.firewall_db.make_firewall_group_dict_with_rules(
                context=context, firewall_group_id=firewall_group_id
            )
        )

        ingress_rules = firewall_group_with_rules["ingress_rule_list"]
        egress_rules = firewall_group_with_rules["egress_rule_list"]

        self.faucet.add_acls_to_vlan_egress(vlan_id=vlan, rules=egress_rules)
        self.faucet.add_acls_to_vlan_ingress(vlan_id=vlan, rules=ingress_rules)

    def _remove_firewall_group_from_ports(self, context, port_ids: list[str]):
        for port_id in port_ids:
            try:
                self._remove_firewall_group_from_port(context=context, port_id=port_id)
            except Exception as e:
                logger.warning(f"Removing firewall for port {port_id} failed: {e}")

    def _remove_firewall_group_from_port(self, context, port_id: str):
        network_segment = self._get_network_segment_from_port(
            context=context, port_id=port_id
        )

        if network_segment.network_type != "vlan":
            logger.warning(
                f"Network type for port {port_id} is {network_segment.type}, firewall group will be ignored"
            )
            return

        vlan = network_segment.segmentation_id

        self.faucet.remove_acl_vlan(vlan_id=vlan)

    def _resync_config(self, context):
        self.faucet.intialize_main_files()

        firewall_groups = self.firewall_db.get_firewall_groups(
            context=context, fields=["id"]
        )

        logger.info(f"resync config firewall groups {firewall_groups}")

        for firewall_group in firewall_groups:
            ports = self.firewall_db.get_ports_in_firewall_group(
                context=context, firewall_group_id=firewall_group["id"]
            )

            logger.info(f"resync_config ports {ports}")

            self._apply_firewall_group_to_ports(
                context=context, port_ids=ports, firewall_group_id=firewall_group["id"]
            )
