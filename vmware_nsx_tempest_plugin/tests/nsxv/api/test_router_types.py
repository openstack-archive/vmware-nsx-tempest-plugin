# Copyright 2015 VMware Inc
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

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest import test
from vmware_nsx_tempest_plugin.services import nsxv_client

CONF = config.CONF


class ExcRouterTest(base.BaseAdminNetworkTest):
    """
    Test class for exclusive router type, which is 1:1 mapping of
    NSX-v service edge. Tests will skipped if the router-type
    extension is not enabled.
    """

    @classmethod
    def skip_checks(cls):
        super(ExcRouterTest, cls).skip_checks()
        if not test.is_extension_enabled('nsxv-router-type', 'network'):
            msg = "router-type extension is not enabled"
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ExcRouterTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(ExcRouterTest, cls).resource_setup()
        cls.tenant_cidr = (CONF.network.project_network_cidr
                           if cls._ip_version == 4 else
                           CONF.network.project_network_v6_cidr)
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for interface in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=interface['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('ac1639a0-2a8d-4c68-bccd-54849fd45f86')
    def test_create_exc_router(self):
        """
        Test create an exclusive router. After creation, check nsx_v
        backend create service for the exclusive router.
        """
        name = data_utils.rand_name('router-')
        router = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False, router_type='exclusive')
        self.addCleanup(self._delete_router, router['router'])
        router_nsxv_name = '%s-%s' % (router['router']['name'],
                                      router['router']['id'])
        self.assertEqual(router['router']['name'], name)
        exc_edge = self.vsm.get_edge(router_nsxv_name)
        self.assertTrue(exc_edge is not None)
        self.assertEqual(exc_edge['edgeType'], 'gatewayServices')

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('c4b94988-0bc7-11e5-9203-0050568833db')
    def test_update_exc_router(self):
        """
        Test update an exclusive router
        """
        name = data_utils.rand_name('router-')
        router = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False, router_type='exclusive')
        self.addCleanup(self._delete_router, router['router'])
        self.assertEqual(router['router']['name'], name)
        updated_name = 'updated' + name
        update_body = self.routers_client.update_router(
            router['router']['id'], name=updated_name)
        self.assertEqual(update_body['router']['name'], updated_name)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('a0ff5afa-0bcc-11e5-9203-0050568833db')
    def test_list_show_exc_router(self):
        """
        Test list and show exclusive router.
        """
        name = data_utils.rand_name('router-')
        router = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False, router_type='exclusive')
        self.addCleanup(self._delete_router, router['router'])
        self.assertEqual(router['router']['name'], name)
        # Show details of exclusive router
        show_body = self.routers_client.show_router(router['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(show_body['router']['admin_state_up'], False)
        # List routers and verify if created router in list
        list_body = self.routers_client.list_routers()
        routers_list = [r['id'] for r in list_body['routers']]
        self.assertIn(router['router']['id'], routers_list)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('adef8d1e-0bce-11e5-9203-0050568833db')
    def test_delete_exc_router(self):
        """
        Test create, update, and delete an exclusive router
        """
        name = data_utils.rand_name('router-')
        router = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False, router_type='exclusive')
        self.assertEqual(router['router']['name'], name)
        # Update the name of the exclusive router
        updated_name = 'updated' + name
        update_body = self.routers_client.update_router(
            router['router']['id'], name=updated_name)
        self.assertEqual(update_body['router']['name'], updated_name)
        # Delete the exclusive router and verify it has been deleted
        # from nsxv backend
        self.routers_client.delete_router(router['router']['id'])
        list_body = self.routers_client.list_routers()
        routers_list = [r['id'] for r in list_body['routers']]
        self.assertNotIn(router['router']['id'], routers_list)
        nsxv_edge_name = "%s-%s" % (name, router['router']['id'])
        self.assertIsNone(self.vsm.get_edge(nsxv_edge_name))
