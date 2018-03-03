# Copyright 2018 VMware Inc
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
from tempest.lib import decorators

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client

import time

CONF = config.CONF

LOG = logging.getLogger(__name__)

USERNAME = "UserName:'com.vmware.nsx.openstack'"


class TestAuditSetUp(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestAuditSetUp, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if not CONF.network.public_network_cidr:
            msg = "public_network_cidr must be defined in network section."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestAuditSetUp, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestAuditSetUp, cls).setup_clients()
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)


class TestAuditOnBehalf(TestAuditSetUp):

    @decorators.idempotent_id('247c84e5-34aa-455a-a60c-d7c623e7bc9c')
    def test_audit_log_network_create(self):
        """
        Test audit log for euser info during the
        create operation of openstack network operations
        """
        audit_network = self.create_topology_network("audit_network")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('network')
        #verify backend for audit log
        #Sleep: Takes a while for network info to be captured in the logs
        time.sleep(100)
        audit_info = self.nsx_client.get_audit_log_info(audit_network['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack network id %s'
                      % audit_network['id'])
            raise Exception('No openstack network audit logs collected')
        match_str = [("euser=\"%s %s" % (audit_userid, audit_tenantid)),
                     USERNAME]
        for data in audit_info['results']:
            if "CreateLogicalSwitch" in data['full_log']:
                if all(x in data['full_log'] for x in match_str):
                    LOG.info('Audit log captured for openstack user:%s \
                             creating logical switch:%s'
                             % (audit_userid, audit_network['id']))

    @decorators.idempotent_id('a35ce30e-09dd-4c22-bcb7-06ae42a0bd18')
    def test_audit_log_update_network(self):
        """
        Test audit log for euser info during
        network update operation through openstack
        """
        audit_network = self.create_topology_network("audit_network")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('network')
        # update network
        updated_network_body = {"name": "tempest_updated_audit_network"}
        self.update_topology_network(audit_network['id'],
                                     **updated_network_body)
        time.sleep(100)
        audit_info = self.nsx_client.get_audit_log_info(audit_network['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack \
                       network id %s' % audit_network['id'])
            raise Exception('No openstack network audit logs collected')
        match_str = [("euser=\"%s %s" % (audit_userid, audit_tenantid)),
                     USERNAME]
        for data in audit_info['results']:
            if "UpdateLogicalSwitch" in data['full_log']:
                if all(x in data['full_log'] for x in match_str):
                    LOG.info('Audit log captured for openstack user:%s \
                             updating logical switch:%s'
                             % (audit_userid, audit_network['id']))
