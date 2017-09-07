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

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF
LOG = constants.log.getLogger(__name__)


class ProviderNetworks(feature_manager.FeatureManager):
    """Test Provider Physical Networks

    1. Create Vxlan Provider networks.
    2. Create Vlan Provider networks.
    3. Create Vlan/Vxlan provider networks using worng ID.
    """

    @classmethod
    def skip_checks(cls):
        super(ProviderNetworks, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderNetworks, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderNetworks, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        out = cls.nsx.get_transport_zones()
        vlan_flag = 0
        vxlan_flag = 0
        for tz in out:
            if "transport_type" in tz.keys() and (vlan_flag == 0
                                                  or vxlan_flag == 0):
                if vxlan_flag == 0 and tz['transport_type'] == "OVERLAY":
                    cls.overlay_id = tz['id']
                    vxlan_flag = 1
                if vlan_flag == 0 and tz['transport_type'] == "VLAN":
                    cls.vlan_id = tz['id']
                    vlan_flag = 1

    def provider_networks_topoloy(self, tz_id, net_type,
                                  admin_state_up=True):
        networks_client = self.cmgr_adm.networks_client
        if net_type == constants.VXLAN_TYPE:
            name = "provider_network_vxlan"
            body = {"provider:physical_network": tz_id,
                    "provider:network_type": net_type,
                    "admin_state_up": admin_state_up}
        elif net_type == constants.VLAN_TYPE:
            name = "provider_network_vlan"
            body = {"provider:segmentation_id": constants.VLAN,
                    "provider:network_type": net_type,
                    "provider:physical_network": tz_id,
                    "admin_state_up": admin_state_up}
        network = self.create_topology_network(name,
                                               networks_client=networks_client,
                                               **body)
        return network

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('75c793ed-fdce-4062-a633-2f0a7af5671d')
    def test_provider_vxlan_network(self):
        provider_network = self.provider_networks_topoloy(self.overlay_id,
                                                          constants.VXLAN_TYPE)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = provider_network['name'] + '_subnet'
        self.create_topology_subnet(subnet_name, provider_network,
                                    subnets_client=subnet_client)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('0307068e-fef1-4d2d-b196-7ffc45c8ec81')
    def test_provider_vxlan_network_with_admin_state_down(self):
        provider_network = self.provider_networks_topoloy(self.overlay_id,
                                                          constants.VXLAN_TYPE,
                                                          admin_state_up=False)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = provider_network['name'] + '_subnet'
        self.create_topology_subnet(subnet_name, provider_network,
                                    subnets_client=subnet_client)

    @decorators.attr(type='nsxv3')
    @decorators.attr(type=["negative"])
    @decorators.idempotent_id('3c316de3-3df4-4a4b-bda4-e5735c7b53cf')
    def test_provider_vlan_network_with_invalid_vlan_tz(self):
        self.vlan_id += "ab"
        self.assertRaises(exceptions.BadRequest,
                          self.provider_networks_topoloy,
                          self.vlan_id, constants.VLAN_TYPE)

    @decorators.attr(type='nsxv3')
    @decorators.attr(type=["negative"])
    @decorators.idempotent_id('03a68787-9700-4aeb-bff5-b9af1a4dacce')
    def test_provider_vxlan_network_with_invalid_vxlan_tz(self):
        self.overlay_id += "ab"
        self.assertRaises(exceptions.BadRequest,
                          self.provider_networks_topoloy,
                          self.overlay_id, constants.VXLAN_TYPE)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('bcede7c9-cc12-4b7e-800c-cf779c718df1')
    def test_provider_vlan_network(self):
        provider_network = self.provider_networks_topoloy(self.vlan_id,
                                                          constants.VLAN_TYPE)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "False"}
        self.create_topology_subnet(subnet_name, provider_network,
                                    subnets_client=subnet_client,
                                    **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('e070ddd8-3caf-4aaf-8430-ffe5076b4a6b')
    def test_provider_vlan_network_with_admin_state_down(self):
        provider_network = self.provider_networks_topoloy(self.vlan_id,
                                                          constants.VLAN_TYPE,
                                                          admin_state_up=False)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "False"}
        self.create_topology_subnet(subnet_name, network,
                                    subnets_client=subnet_client,
                                    **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('fe1598bb-c36e-4585-b441-927737df781e')
    def test_provider_vlan_network_with_vxlan_tz(self):
        self.assertRaises(exceptions.BadRequest,
                          self.provider_networks_topoloy,
                          self.overlay_id, constants.VLAN_TYPE)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('13d8959c-fc49-49fc-9b03-51ea07313257')
    def test_provider_vxlan_network_with_vlan_tz(self):
        self.assertRaises(exceptions.BadRequest,
                          self.provider_networks_topoloy,
                          self.vlan_id, constants.VXLAN_TYPE)
