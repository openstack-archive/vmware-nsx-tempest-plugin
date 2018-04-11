# All Rights Reserved.
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.lib import feature_manager


CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestZonesV2Ops(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestZonesV2Ops, cls).skip_checks()
        if not test.is_extension_enabled('designate', 'network'):
            msg = "Extension designate is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestZonesV2Ops, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestZonesV2Ops, cls).setup_clients()


class TestZones(TestZonesV2Ops):

    excluded_keys = ['created_at', 'updated_at', 'version', 'links',
                    'status', 'action']

    @decorators.idempotent_id('e26cf8c6-164d-4097-b066-4e2100382d53')
    def test_create_zone(self):
        """Creating a v2 Zone"""
        LOG.info('Create a zone')
        zone = self.create_zone(wait_until=True)
        LOG.info('Ensure we respond with CREATE+PENDING')
        self.assertEqual('CREATE', zone['action'])
        self.assertEqual('PENDING', zone['status'])

    @decorators.idempotent_id('76586e1f-7466-4dd1-bcdf-b6805c63731c')
    def test_delete_zone(self):
        LOG.info('Create a zone')
        zone = self.create_zone()
        LOG.info('Delete the zone')
        body = self.delete_zone(zone['id'])
        LOG.info('Ensure we respond with DELETE+PENDING')
        self.assertEqual('DELETE', body['action'])
        self.assertEqual('PENDING', body['status'])

    @decorators.idempotent_id('3fa18ce7-ac47-425f-a1d1-2baa5ead0ed1')
    def test_show_zone(self):
        LOG.info('Create a zone')
        zone = self.create_zone()
        LOG.info('Fetch the zone')
        body = self.show_zone(zone['id'])
        LOG.info('Ensure the fetched response matches the created zone')
        self.assertEqual(zone['links'], body[1]['links'])
        self.assertEqual(zone['name'], body[1]['name'])
        self.assertEqual(zone['email'], body[1]['email'])
        self.assertEqual(zone['ttl'], body[1]['ttl'])

    @decorators.idempotent_id('7e35c62c-5baf-4d32-b3e8-59e76ea6571f')
    def test_list_zones(self):
        LOG.info('Create a zone')
        self.create_zone()
        LOG.info('List zones')
        body = self.list_zones()
        self.assertGreater(len(body[1]['zones']), 0)

    @decorators.idempotent_id('55ca3fc8-6652-4f00-9af8-c01ea5bae5a0')
    def test_update_zone(self):
        LOG.info('Create a zone')
        zone = self.create_zone()
        # Generate a random description
        description = data_utils.rand_name()
        LOG.info('Update the zone')
        zone = self.update_zone(
            zone['id'], email=zone['email'], ttl=zone['ttl'],
            description=description, wait_until=True)
        LOG.info('Ensure we respond with UPDATE+PENDING')
        self.assertEqual('UPDATE', zone['action'])
        self.assertEqual('PENDING', zone['status'])
        LOG.info('Ensure we respond with updated values')
        self.assertEqual(description, zone['description'])
