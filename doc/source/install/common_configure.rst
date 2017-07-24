2. Edit the ``/etc/vmware-nsx-tempest-plugin/vmware-nsx-tempest-plugin.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://vmware-nsx-tempest-plugin:VMWARE-NSX-TEMPEST-PLUGIN_DBPASS@controller/vmware-nsx-tempest-plugin
