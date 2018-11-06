#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import re

from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

CONF = config.CONF


class TestBarbican(feature_manager.FeatureManager):

    """Test Barbican APU cases

    """
    @classmethod
    def setup_clients(cls):
        super(TestBarbican, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.routers_client = cls.cmgr_adm.routers_client
        cls.networks_client = cls.cmgr_adm.networks_client
        cls.subnets_client = cls.cmgr_adm.subnets_client
        cls.sec_rule_client = cls.cmgr_adm.security_group_rules_client
        cls.sec_client = cls.cmgr_adm.security_groups_client

    @classmethod
    def resource_setup(cls):
        super(TestBarbican, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

        cls.namestart = 'lbaas-ops'
        cls.poke_counters = 12
        cls.hm_delay = 4
        cls.hm_max_retries = 3
        cls.hm_timeout = 10
        cls.server_names = []
        cls.loadbalancer = None
        cls.vip_fip = None
        cls.web_service_start_delay = 2.5

    @decorators.idempotent_id('2e13d4bb-54de-463a-a358-0fb9a221d8f3')
    def test_barbican_multiple_secret_and_container(self):
        """
        Create multiple barbican secets and container
        """
        for i in range(1, 51):
            self.create_barbican_secret_conatainer(
                constants.CERT_FILE, constants.KEY_FILE)

    @decorators.idempotent_id('7d46a170-6b3b-4f4d-903a-b29aebb93289')
    def test_barbican_secret_update(self):
        """
        Update barbican secret
        """
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "name": secret_name1}
        barbican_secret1 = self.create_barbican_secret(**kwargs)
        uuid = self._get_uuid(barbican_secret1['secret_ref'])
        self.secret_client.put_secret_payload(uuid, cert_content)

    @decorators.idempotent_id('2b0c1707-afc3-4674-a6c6-4dc42f318117')
    def test_barbican_secret_create_with_octet_stream(self):
        """
        Create barbican secret with octet stream
        """
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": "symmetric",
                  "algorithm": "binary",
                  "payload_content_type": "application/octet-stream",
                  "payload_content_encoding": "base64",
                  "mode": constants.MODE,
                  "bit_length": constants.BIT_LENGTH,
                  "payload": cert_content,
                  "name": secret_name1}
        self.create_barbican_secret(**kwargs)

    @decorators.idempotent_id('c5caa619-1e43-4724-8d94-a61ff7025a07')
    def test_barbican_delete_secret_container_with_invalid_uuid(self):
        """
        Delete barbican conrainer with
        invalid barbican container id
        """
        secert_id = uuidutils.generate_uuid()
        self.assertRaises(exceptions.NotFound,
                          self.secret_client.delete_secret,
                          secert_id)
        container_id = uuidutils.generate_uuid()
        self.assertRaises(exceptions.NotFound,
                          self.container_client.delete_container,
                          container_id)

    @decorators.idempotent_id('9aee2ad3-5b61-4451-8ccc-a727bbe4618a')
    def test_barbican_secret_create_with_wrong_bit_length(self):
        """
        Create barbican secret with wrong bit length
        """
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "payload_content_type": constants.PAYLOAD_CONTENT_TYPE,
                  "mode": constants.MODE,
                  "bit_length": 6382372,
                  "payload": cert_content,
                  "name": secret_name1}
        self.assertRaises(exceptions.BadRequest,
                          self.create_barbican_secret, **kwargs
                          )
