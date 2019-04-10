# Copyright 2017 VMware Inc
# All Rights Reserved
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
from oslo_log import log as logging

from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxp_client

LOG = logging.getLogger(__name__)


class NSXClient(object):
    """Base NSX REST client"""
    def __init__(self, backend, host, username, password, *args, **kwargs):
        self.backend = backend.lower()
        self.host = host
        self.username = username
        self.password = password
        if backend.lower() == "nsxv3":
            self.nsx = nsxv3_client.NSXV3Client(host, username, password)
        elif backend.lower() == "nsxp":
            self.nsx = nsxp_client.NSXPClient(host, username, password)

    def get_firewall_section_and_rules(self, *args, **kwargs):
        if self.backend == "nsxv3":
            firewall_section = self.nsx.get_firewall_section(
                *args, **kwargs)
            firewall_section_rules = self.nsx.get_firewall_section_rules(
                firewall_section)
            return firewall_section, firewall_section_rules
        elif self.backend == "nsxp":
            firewall_section = self.nsx.get_firewall_section(
                *args, **kwargs)
            firewall_section_rules = self.nsx.get_firewall_section_rules(
                firewall_section, kwargs['os_tenant_id'])
            return firewall_section, firewall_section_rules
        else:
            # TODO(ddoshi) define else for nsxv
            pass

    def get_bridge_cluster_info(self, *args, **kwargs):
        if self.backend == "nsxv3":
            return self.nsx.get_bridge_cluster_info(
                *args, **kwargs)

    def get_bridge_profile_info(self, *args, **kwargs):
        if self.backend == "nsxv3":
            return self.nsx.get_bridge_profile_info(
                *args, **kwargs)

    def get_qos_switching_profile(self, policy_name):
        """
        Retrieve attributes of a given nsx switching profile
        """
        if self.backend == "nsxv3":
            qos_policies = self.nsx.get_switching_profiles()
            nsx_policy = self.nsx.get_nsx_resource_by_name(qos_policies,
                                                           policy_name)
            qos_policy = self.nsx.get_switching_profile(nsx_policy['id'])
            return qos_policy
        else:
            # TODO(dkandavarajay) define else for NSXV
            pass

    def get_qos_bandwidth_rule(self, nsx_policy_id):
        """
        Retrieve attributes of a given nsx qos bandwidth-rule
        """
        if self.backend == "nsxv3":
            sw_profiles = self.nsx.get_switching_profile(nsx_policy_id)
            shaper_cfg = sw_profiles['shaper_configuration']
            for cfg in shaper_cfg:
                if cfg['resource_type'] == 'IngressRateShaper':
                    avg_bw = cfg['average_bandwidth_mbps']
                    peak_bw = cfg['peak_bandwidth_mbps']
                    max_burst = cfg['burst_size_bytes']
                    return avg_bw, peak_bw, max_burst
        else:
            # TODO(dkandavarajay) define else for NSXV
            pass

    def get_qos_dscp_rule(self, nsx_policy_id):
        """
        Retrieve attributes of a given nsx qos bandwidth-rule
        """
        if self.backend == "nsxv3":
            sw_profiles = self.nsx.get_switching_profile(nsx_policy_id)
            shaper_cfg = sw_profiles['dscp']
            return shaper_cfg['priority']
        else:
            # TODO(dkandavarajay) define else for NSXV
            pass
        return None

    def get_audit_log_info(self, obj_id):
        """
        Retrieve audit log information for openstack user
        """
        if self.backend == "nsxv3":
            output = self.nsx.get_audit_log(obj_id)
            return output
        else:
            pass
        return None
