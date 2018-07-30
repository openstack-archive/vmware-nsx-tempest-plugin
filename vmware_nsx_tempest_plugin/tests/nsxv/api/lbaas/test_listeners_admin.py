# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as ex

from vmware_nsx_tempest_plugin.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class ListenersTest(base.BaseAdminTestCase):

    """Tests the listener creation operation in admin scope

    in the Neutron-LBaaS API using the REST client for Listeners:

    """

    @classmethod
    def resource_setup(cls):
        super(ListenersTest, cls).resource_setup()
        cls.create_lb_kwargs = {'tenant_id': cls.subnet['tenant_id'],
                                'vip_subnet_id': cls.subnet['id']}
        cls.load_balancer = cls._create_active_load_balancer(
            **cls.create_lb_kwargs)
        cls.protocol = 'HTTP'
        cls.port = 80
        cls.load_balancer_id = cls.load_balancer['id']
        cls.create_listener_kwargs = {'loadbalancer_id': cls.load_balancer_id,
                                      'protocol': cls.protocol,
                                      'protocol_port': cls.port}
        cls.listener = cls._create_listener(
            **cls.create_listener_kwargs)
        cls.listener_id = cls.listener['id']

    @classmethod
    def resource_cleanup(cls):
        super(ListenersTest, cls).resource_cleanup()

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f84bfb35-7f73-4576-b2ca-26193850d2bf')
    def test_create_listener_empty_tenant_id(self):
        """Test create listener with an empty tenant id should fail

        Kilo: @decorators.skip_because(bug="1638738")
        """
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8081
        create_new_listener_kwargs['tenant_id'] = ""
        self.assertRaises(ex.BadRequest,
                          self._create_listener,
                          **create_new_listener_kwargs)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id])

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('71ebb8d6-ff2a-410d-a089-b086f195609d')
    def test_create_listener_invalid_tenant_id(self):
        """Test create listener with an invalid tenant id"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8082
        create_new_listener_kwargs['tenant_id'] = "&^%123"
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('55eaeab9-a21e-470c-8861-5af1ded9d64a')
    def test_create_listener_missing_tenant_id(self):
        """Test create listener with an missing tenant id.

        Verify that creating a listener in admin scope with
        a missing tenant_id creates the listener with admin
        tenant_id.
        """
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8083
        admin_listener = self._create_listener(
            **create_new_listener_kwargs)
        admin_listener_id = admin_listener['id']
        self.addCleanup(self._delete_listener, admin_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, admin_listener_id])
        listener = self._show_listener(admin_listener_id)
        self.assertEqual(admin_listener, listener)
        self.assertEqual(admin_listener.get('tenant_id'),
                         listener.get('tenant_id'))
