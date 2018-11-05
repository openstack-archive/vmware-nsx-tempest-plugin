# Copyright 2018 VMware Inc
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

import re

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client
from vmware_nsx_tempest_plugin.common import constants
from tempest.lib.common.utils import test_utils

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class QosUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Qos policies and ports with
       Qos policies attached
    """
    @classmethod
    def setup_clients(cls):
        super(QosUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.routers_client = cls.cmgr_adm.routers_client
        cls.networks_client = cls.cmgr_adm.networks_client
        cls.subnets_client = cls.cmgr_adm.subnets_client
        cls.ports_client = cls.cmgr_adm.ports_client

    @classmethod
    def resource_setup(cls):
        super(QosUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_network_topology(self):
        """
        Create network and subnet with /21 cidr to have 2000
        ips to allocate to the ports created.
        """
        network_name = data_utils.rand_name(name='tempest-net')
        subnet_name = data_utils.rand_name(name='tempest-subnet')
        network = self.create_topology_network(network_name)
        subnet = self.create_topology_subnet(
            subnet_name, network, cidr=constants.CIDR_SCALE_QOS)
        topology = dict(network=network, subnet=subnet)
        return topology

    def _create_scale_qos_policies(self, scale):
        for value in range(scale):
            name = "uniscale-{}-qos".format(value)
            policy = self.create_qos_policy(name,
                                            description='scale',
                                            shared=False)
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.delete_qos_policy,
                            policy['id'])
        qos_policies = self.list_qos_policies()
        scale_policies = [pol for pol in qos_policies
                          if pol['name'].startswith('uniscale-')]
        self.assertEqual(len(scale_policies), scale,
                         "policies count doesnt equal scale value")
        l_p = self.nsx_client.nsx.get_logical_resources("/switching-profiles")
        nsx_policies = [i for i in l_p
                        if "QosSwitchingProfile" in i['resource_type']]
        nsx_policy = [pol for pol in nsx_policies
                      if pol['display_name'].startswith('uniscale-')]
        self.assertEqual(len(nsx_policy), scale,
                         "QoS policies on backend not equals scale")

    def _create_scale_ports(self, scale, network):
        body = dict()
        qos_policies = [policy for policy in self.list_qos_policies()
                        if policy['name'].startswith('uniscale')]
        for value in range(scale):
            body['qos_policy_id'] = qos_policies[value]['id']
            body['name'] = "uniscale-{}-port".format(value)
            self.create_topology_port(network,
                                      ports_client=self.ports_client,
                                      **body)
        ports_list = self.ports_client.list_ports()['ports']
        uniscale_port = [i for i in ports_list
                         if i['name'].startswith("uniscale-")]
        self.assertEqual(len(uniscale_port), scale,
                         "count of uniscale ports doesnt match")
        port_l = [i for i in self.nsx.get_logical_ports()]
        nsx_ports = [i for i in port_l
                     if i['display_name'].startswith("uniscale-")]
        self.assertEqual(len(nsx_ports), scale,
                         "ports on backend doesnt match")

    def _fetch_ports_random(self):
        # get all the qos policies list
        qos_policies = [policy['id'] for policy in self.list_qos_policies()
                        if policy['name'].startswith('uniscale')]

        # get ports from db and verify qos
        ports_list = self.ports_client.list_ports()['ports']
        uniscale_port = [i for i in ports_list
                         if i['name'].startswith("uniscale-")]
        # verify ports have got qos assigned
        for port in uniscale_port:
            port_qos = port['qos_policy_id']
            self.assertIn(port_qos, qos_policies)

        # List qos policy switching profile ids on backend
        l_p = self.nsx_client.nsx.get_logical_resources("/switching-profiles")
        nsx_policies = [i for i in l_p
                        if "QosSwitchingProfile" in i['resource_type']]
        nsx_policy = [policy['id'] for policy in nsx_policies
                      if policy['display_name'].startswith('uniscale-')]

        # verify ports on backend gave got qos assigned
        port_l = [i for i in self.nsx.get_logical_ports()]
        nsx_ports = [i for i in port_l
                     if i['display_name'].startswith("uniscale-")]
        val = [i for i in nsx_ports]
        value = [i['switching_profile_ids'] for i in val]
        val1 = [i for i in value]
        qos = [[i['value'] for i in l
                if i['key'] == 'QosSwitchingProfile'] for l in val1]
        for port_qos in qos:
            self.assertIn(port_qos, nsx_policy)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_1k_qos_policies(self):
        self._create_scale_qos_policies(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_2k_qos_policies(self):
        self._create_scale_qos_policies(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_4k_qos_policies(self):
        self._create_scale_qos_policies(4000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5ba22b0f-4593-4509-8998-a3002ce63406')
    def test_create_2k_ports(self):
        topology = self._create_network_topology()
        self._create_scale_qos_policies(20)
        self._create_scale_ports(10, topology['network'])
        self._fetch_ports_random()
