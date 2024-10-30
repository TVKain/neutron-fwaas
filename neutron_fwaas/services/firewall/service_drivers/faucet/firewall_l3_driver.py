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

#                      |                                                  ACL HERE          |
#                      |                                                      |             |
#                      |                               |--------|             |             |
# external vlan network|-----(external-port)-----------| Router |-----(internal port)-------|internal vlan network
#                      |                               |--------|                           |
#                      |                                                                    |
#                      |                                                                    |


import logging

from oslo_config import cfg

from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_lib import constants as const

from neutron_fwaas.services.firewall.service_drivers.faucet.faucet import FaucetFirewallManager

from neutron_fwaas.temp.log import logger

LOG = logging.getLogger(__name__)

class FaucetFwaasDriver(driver_api.FirewallDriverDB):
    def __init__(self, service_plugin):
        super(FaucetFwaasDriver, self).__init__(service_plugin)
        logger.info("In constructor of faucet")
        
        self.faucet = FaucetFirewallManager()
        self._mech = None
        
        self.faucet.intialize_main_files()

    def is_supported_l2_port(self, port):
        return False

    def is_supported_l3_port(self, port):
        return True

    def start_rpc_listener(self):
        return []
    
    
    def create_firewall_group_precommit(self, context, firewall_group):        
        if not firewall_group['ports']:
            LOG.info("khanhtv28 No ports bound to firewall_group: %s, "
                     "setting this to inactive", firewall_group['id'])
            status = const.INACTIVE
        else:
            status = const.PENDING_CREATE
        firewall_group['status'] = status
        

    def create_firewall_group_postcommit(self, context, firewall_group):
        try:
            if firewall_group['ingress_firewall_policy_id'] or firewall_group['egress_firewall_policy_id']:
                LOG.info("khanhtv28 contains ingress or egress firewall policy")
            if firewall_group['ports']:
                firewall_group['status'] = const.ACTIVE
                LOG.info("khanhtv28 firewall contains port")
        except Exception:
            LOG.error("Failed to create_firewall_group_postcommit.")
            raise
        else:
            self.firewall_db.update_firewall_group_status(
                context, firewall_group['id'], firewall_group['status'])
        
    
    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        port_updated = (set(new_firewall_group['ports']) !=
                        set(old_firewall_group['ports']))
        policies_updated = (
                new_firewall_group['ingress_firewall_policy_id'] !=
                old_firewall_group['ingress_firewall_policy_id'] or
                new_firewall_group['egress_firewall_policy_id'] !=
                old_firewall_group['egress_firewall_policy_id']
        )
        if port_updated or policies_updated:
            new_firewall_group['status'] = const.PENDING_UPDATE

    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        if new_firewall_group['status'] != const.PENDING_UPDATE:
            return
        old_ports = set(old_firewall_group['ports'])
        new_ports = set(new_firewall_group['ports'])
        old_ing_policy = old_firewall_group['ingress_firewall_policy_id']
        new_ing_policy = new_firewall_group['ingress_firewall_policy_id']
        old_eg_policy = old_firewall_group['egress_firewall_policy_id']
        new_eg_policy = new_firewall_group['egress_firewall_policy_id']
        
        ## For now we'll ignore the policies 

        # If there's no ports we'll just set it inactive
        if not new_ports:
            LOG.info("No ports bound to firewall_group: %s, "
                     "set it to inactive", new_firewall_group['id'])
            new_firewall_group['status'] = const.INACTIVE

        if new_ports: 
            LOG.info("Contains new ports") 
            new_firewall_group['status'] = const.ACTIVE


        self.firewall_db.update_firewall_group_status(
            context, new_firewall_group['id'],
            new_firewall_group['status'])
        
    def delete_firewall_group_precommit(self, context, firewall_group):
        LOG.info("khanhtv28 delete firewall group precommit")


    def delete_firewall_group_postcommit(self, context, firewall_group):
        LOG.info("khanhtv28 delete firewall group postcommit")


    # Firewall Policy
    def create_firewall_policy_precommit(self, context, firewall_policy):
        pass

    def create_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def update_firewall_policy_precommit(self, context, old_firewall_policy,
                                         new_firewall_policy):
        pass

    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_policy):
        pass

    def delete_firewall_policy_precommit(self, context, firewall_policy):
        LOG.info("khanhtv28 delete firewall group policy precommit")

    def delete_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    # Firewall Rule
    def create_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def create_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def update_firewall_rule_precommit(self, context, old_firewall_rule,
                                       new_firewall_rule):
        raise NotImplementedError

    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        raise NotImplementedError

    def delete_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def delete_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def insert_rule_precommit(self, context, policy_id, rule_info):
        pass

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_precommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        pass
    
    def _get_vlan_id_from_port(self):
        pass