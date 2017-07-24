Prerequisites
-------------

Before you install and configure the openstack service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``vmware-nsx-tempest-plugin`` database:

     .. code-block:: none

        CREATE DATABASE vmware-nsx-tempest-plugin;

   * Grant proper access to the ``vmware-nsx-tempest-plugin`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON vmware-nsx-tempest-plugin.* TO 'vmware-nsx-tempest-plugin'@'localhost' \
          IDENTIFIED BY 'VMWARE-NSX-TEMPEST-PLUGIN_DBPASS';
        GRANT ALL PRIVILEGES ON vmware-nsx-tempest-plugin.* TO 'vmware-nsx-tempest-plugin'@'%' \
          IDENTIFIED BY 'VMWARE-NSX-TEMPEST-PLUGIN_DBPASS';

     Replace ``VMWARE-NSX-TEMPEST-PLUGIN_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``vmware-nsx-tempest-plugin`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt vmware-nsx-tempest-plugin

   * Add the ``admin`` role to the ``vmware-nsx-tempest-plugin`` user:

     .. code-block:: console

        $ openstack role add --project service --user vmware-nsx-tempest-plugin admin

   * Create the vmware-nsx-tempest-plugin service entities:

     .. code-block:: console

        $ openstack service create --name vmware-nsx-tempest-plugin --description "openstack" openstack

#. Create the openstack service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        openstack public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        openstack internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        openstack admin http://controller:XXXX/vY/%\(tenant_id\)s
