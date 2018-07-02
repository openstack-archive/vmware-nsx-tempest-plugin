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
import time

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest.common import constants as const
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


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
    success = 0

    @decorators.idempotent_id('247c84e5-34aa-455a-a60c-d7c623e7bc9c')
    def test_audit_log_network_create(self):
        """
        Test audit log for euser info during the
        create operation of openstack network
        """
        audit_network = self.create_topology_network("audit_network")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('network')
        #verify backend for audit log
        #Sleep: Takes a while for network info to be captured in the logs
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_network['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack network id %s'
                      % audit_network['id'])
            raise Exception('No openstack network audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "CreateLogicalSwitch" in data['full_log']:
                if match_str in data['full_log']:
                    LOG.info('Audit log captured for openstack user:%s '
                             'creating logical switch:%s'
                             % (audit_userid, audit_network['id']))
                    self.success = 1
                    break
        if self.success != 1:
            raise Exception('Create network log does not contain entry for'
                            'openstack user id %s' % audit_userid)

    @decorators.idempotent_id('a35ce30e-09dd-4c22-bcb7-06ae42a0bd18')
    def test_audit_log_update_network(self):
        """
        Test audit log for euser info during
        network update operation through openstack
        """
        audit_network = self.create_topology_network("audit_network")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('network')
        # update network name
        updated_name = "tempest_updated_audit_network"
        updated_network_body = {"name": updated_name}
        updated_ntwk = self.update_topology_network(audit_network['id'],
                                     **updated_network_body)
        self.assertEqual(updated_ntwk['network']['name'], updated_name)
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_network['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack'
                      ' network id %s' % audit_network['id'])
            raise Exception('No openstack network audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "UpdateLogicalSwitch" in data['full_log']:
                if match_str in data['full_log']:
                    self.success = 1
                    LOG.info('Audit log captured for openstack user:%s'
                             ' updating logical switch:%s'
                             % (audit_userid, audit_network['id']))
                    break
        if self.success != 1:
            raise Exception("Update network log does not contain entry"
                            " for openstack user id %s" % audit_userid)

    @decorators.idempotent_id('c95856d1-f8df-4373-ae8d-1272aa58f867')
    def test_audit_log_delete_network(self):
        """
        Test audit log for euser info during
        network delete operation through openstack
        """
        audit_network = self.create_topology_network("audit_network")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('network')
        # delete the network
        self.delete_topology_network(audit_network['id'])
        time.sleep(const.AUDIT_WAIT_TIME)
        filter_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        audit_info = self.nsx_client.get_audit_log_info(filter_str)
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching delete operation'
                      'of openstack network id %s' % audit_network['id'])
            raise Exception('No openstack network audit logs collected')
        match_str = 'DeleteLogicalSwitch'
        for data in audit_info['results']:
            if match_str in data['full_log']:
                self.success = 1
                LOG.info('Audit log captured for openstack user:%s'
                         'deleting logical switch:%s'
                         % (audit_userid, audit_network['id']))
            else:
                continue
            break
        if self.success != 1:
            raise Exception('Delete log does not contain entry for'
                            'the openstack user id %s' % audit_userid)

    @decorators.idempotent_id('11617fd0-6052-4b39-be20-a3f981ea2636')
    def test_audit_log_create_router(self):
        """
        Test audit log for euser info during the
        create operation of openstack router
        """
        audit_router = self.create_topology_router("audit_router")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('router')
        #verify backend for audit log
        #Sleep: Takes a while for router info to be captured in the logs
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_router['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack router id %s'
                      % audit_router['id'])
            raise Exception('No openstack router audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "CreateLogicalRouter" in data['full_log']:
                if match_str in data['full_log']:
                    LOG.info('Audit log captured for openstack user:%s'
                             'creating logical router:%s'
                             % (audit_userid, audit_router['id']))
                    self.success = 1
                    break
        if self.success != 1:
            raise Exception('Create router log does not contain entry'
                            'for openstack user id %s' % audit_userid)

    @decorators.idempotent_id('909d6970-53c6-4402-a3f1-1ff3dc733209')
    def test_audit_log_update_router(self):
        """
        Test audit log for euser info during
        router update operation through openstack
        """
        audit_router = self.create_topology_router("audit_router")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('router')
        # update router name
        updated_name = "tempest_updated_audit_rtr"
        updated_rtr_body = {"name": updated_name}
        updated_rtr = self.update_topology_router(audit_router['id'],
                                     **updated_rtr_body)
        self.assertEqual(updated_rtr['router']['name'], updated_name)
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_router['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack'
                      'router id %s' % audit_router['id'])
            raise Exception('No openstack router audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "UpdateLogicalRouter" in data['full_log']:
                if match_str in data['full_log']:
                    self.success = 1
                    LOG.info('Audit log captured for openstack user:%s'
                             'updating logical router:%s'
                             % (audit_userid, audit_router['id']))
                    break
        if self.success != 1:
            raise Exception("Update router log does not contain entry"
                            "for openstack user id %s" % audit_userid)

    @decorators.idempotent_id('90761c77-ab7b-44c5-9974-cfc922c00d07')
    def test_audit_log_delete_router(self):
        """
        Test audit log for euser info during
        router delete operation through openstack
        """
        audit_router = self.create_topology_router("audit_router")
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('router')
        # delete the network
        self.delete_topology_router(audit_router['id'])
        time.sleep(const.AUDIT_WAIT_TIME)
        filter_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        audit_info = self.nsx_client.get_audit_log_info(filter_str)
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching delete operation'
                      'of openstack router id %s' % audit_router['id'])
            raise Exception('No openstack router audit logs collected')
        match_str = 'DeleteLogicalRouter'
        for data in audit_info['results']:
            if match_str in data['full_log']:
                self.success = 1
                LOG.info('Audit log captured for openstack user:%s'
                         'deleting logical router:%s' %
                         (audit_userid, audit_router['id']))
                break
            else:
                continue
        if self.success != 1:
            raise Exception('Delete Router log does not contain entry'
                            ' for the openstack user id %s' % audit_userid)

    @decorators.idempotent_id('2ebe7253-cac0-46e2-94d9-fd2c7bff47fa')
    def test_audit_log_create_security_group(self):
        """
        Test audit log for euser info during the
        create operation of openstack security group
        """
        audit_sg = self.create_topology_security_group()
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('sg')
        #verify backend for audit log
        #Sleep: Takes a while for sg info to be captured in the logs
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_sg['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack sg id %s'
                      % audit_sg['id'])
            raise Exception('No openstack sg audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "CreateNSGroup" in data['full_log']:
                if match_str in data['full_log']:
                    LOG.info('Audit log captured for openstack user:%s '
                             'creating security group:%s'
                             % (audit_userid, audit_sg['id']))
                    self.success = 1
                    break
        if self.success != 1:
            raise Exception('Create security group log does not contain entry '
                            'for openstack user id %s' % audit_userid)

    @decorators.idempotent_id('76bd1ad0-4ecd-47e8-99f9-fb88a8058ff4')
    def test_audit_log_update_security_group(self):
        """
        Test audit log for euser info during
        sg update operation through openstack
        """
        audit_sg = self.create_topology_security_group()
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('sg')
        # update security group name
        updated_name = "tempest_updated_sg"
        updated_sg_body = {"name": updated_name}
        updated_sg = self.update_topology_security_group(audit_sg['id'],
                                     **updated_sg_body)
        self.assertEqual(updated_sg['security_group']['name'], updated_name)
        time.sleep(const.AUDIT_WAIT_TIME)
        audit_info = self.nsx_client.get_audit_log_info(audit_sg['id'])
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching the openstack'
                      ' security group id %s' % audit_sg['id'])
            raise Exception('No openstack security group audit logs collected')
        match_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        for data in audit_info['results']:
            if "UpdateNSGroup" in data['full_log']:
                if match_str in data['full_log']:
                    self.success = 1
                    LOG.info('Audit log captured for openstack user:%s'
                             ' updating security group:%s'
                             % (audit_userid, audit_sg['id']))
                    break
        if self.success != 1:
            raise Exception("Update sg log does not contain entry"
                            " for openstack user id %s" % audit_userid)

    @decorators.idempotent_id('a20bebc7-5773-4086-9ccc-54d8548e37ae')
    def test_audit_log_delete_security_group(self):
        """
        Test audit log for euser info during
        sg delete operation through openstack
        """
        audit_sg = self.create_topology_security_group()
        # get the user id and tenant id
        audit_userid, audit_tenantid = self.get_user_id('sg')
        # delete the security group
        self.delete_topology_security_group(audit_sg['id'])
        time.sleep(const.AUDIT_WAIT_TIME)
        filter_str = "euser=\"%s %s" % (audit_userid, audit_tenantid)
        audit_info = self.nsx_client.get_audit_log_info(filter_str)
        if audit_info['result_count'] == 0:
            LOG.error('No audit log matching delete operation'
                      ' of openstack security group id %s' % audit_sg['id'])
            raise Exception('No openstack security group logs collected')
        match_str = 'DeleteNSGroup'
        for data in audit_info['results']:
            if match_str in data['full_log']:
                self.success = 1
                LOG.info('Audit log captured for openstack user:%s'
                         ' deleting security group:%s' %
                         (audit_userid, audit_sg['id']))
                break
            else:
                continue
        if self.success != 1:
            raise Exception('Delete security group log does not contain entry'
                            ' for the openstack user id %s' % audit_userid)
