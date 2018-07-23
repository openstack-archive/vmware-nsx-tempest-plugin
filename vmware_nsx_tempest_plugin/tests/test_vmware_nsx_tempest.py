# -*- coding: utf-8 -*-

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

"""
test_vmware_nsx_tempest
----------------------------------

Tests for `vmware_nsx_tempest_plugin` module.
"""

from tempest.lib import decorators
from vmware_nsx_tempest_plugin.tests import base


class TestVmware_nsx_tempest(base.TestCase):

    @decorators.idempotent_id('3c4c36a1-684b-4e89-8e71-a328f19324a0')
    def test_something(self):
        pass
