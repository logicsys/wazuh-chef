# Wazuh Manager cookbook

This cookbook installs and configure Wazuh Manager on specified nodes.

There are two types of manager installations:

1. Without filebeat-oss
2. With filebeat-oss

Dependending on your choice, install elastic-stack or opendistro cookbooks respectively.

### Attributes 

* ``api.rb`` contains API IP and port
* ``versions.rb`` contains version attributes to make it easier when it comes to bump version
* The rest of files contains all the default configuration files in order to generate ossec.conf 

Check ['ossec.conf'](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/) documentation
to see all configuration sections.

### Usage

Create a role, `wazuh_server`. Add attributes per above as needed to customize the installation.

```
  {
    "name": "wazuh_server",
    "description": "Wazuh Server host",
    "json_class": "Chef::Role",
    "default_attributes": {

    },
    "override_attributes": {

    },
    "chef_type": "role",
    "run_list": [
      "recipe[wazuh_manager::default]",
      "recipe['filebeat::default]"
    ],
    "env_run_lists": {

    }
  }
```

If you want to build a Wazuh cluster, you need to create two roles, one role for the **Master** and another one for **Worker**:

```
  {
    "name": "wazuh_manager_master",
    "description": "Wazuh Manager master node",
    "json_class": "Chef::Role",
    "default_attributes": {

    },
    "override_attributes": {
      "ossec": {
        "cluster_disabled": "no",
        "conf": {
          "server": {
            "cluster": {
              "node_name": "master01",
              "node_type": "master",
              "disabled": "no",
              "nodes": {
                "node": ["172.16.10.10", "172.16.10.11"]
              "key": "596f6b328c8ca831a03f7c7ca8203e8b"
            }
          }
        }
    },
    "chef_type": "role",
    "run_list": [
      "recipe[wazuh_manager::default]",
      "recipe[filebeat::default]"
    ],
    "env_run_lists": {

    }
  }

  {
    "name": "wazuh_manager_worker",
    "description": "Wazuh Manager worker node",
    "json_class": "Chef::Role",
    "default_attributes": {

    },
    "override_attributes": {
      "ossec": {
        "cluster_disabled": "no",
        "conf": {
          "server": {
            "cluster": {
              "node_name": "worker01",
              "node_type": "worker",
              "disabled": "no",
              "nodes": {
                "node": ["172.16.10.10", "172.16.10.11"]
              "key": "596f6b328c8ca831a03f7c7ca8203e8b"
            }
          }
        }
    },
    "chef_type": "role",
    "run_list": [
      "recipe[wazuh_manager::default]",
      "recipe[filebeat::default]"
    ],
    "env_run_lists": {

    }
  }
```

Check [cluster documentation](https://documentation.wazuh.com/current/user-manual/configuring-cluster/index.html) for more details

### Data Bags for Passwords and Certificates

This cookbook supports using encrypted data bags to securely store sensitive data like passwords and certificates.

#### Creating an Encrypted Data Bag

First, create or use an existing encryption key:

```bash
# Generate a new encryption key (if you don't have one)
openssl rand -base64 512 | tr -d '\r\n' > /path/to/encrypted_data_bag_secret

# Ensure proper permissions
chmod 600 /path/to/encrypted_data_bag_secret
```

#### Password Data Bag

Create a data bag to store the indexer password:

```bash
# Create the data bag
knife data bag create wazuh_secrets

# Create the data bag item with encryption
knife data bag create wazuh_secrets passwords --secret-file /path/to/encrypted_data_bag_secret
```

The data bag item should contain:

```json
{
  "id": "passwords",
  "indexer_password": "your_secure_password_here"
}
```

Then set the password in your role or environment by loading from the data bag in a wrapper cookbook, or set it directly in attributes:

```ruby
# In a wrapper cookbook recipe
secrets = data_bag_item('wazuh_secrets', 'passwords')
node.override['wazuh_manager']['indexer']['password'] = secrets['indexer_password']
```

#### Certificate Data Bag

To store certificates in a data bag, create an item with the certificate content:

```bash
# Create the data bag item
knife data bag create wazuh_secrets manager_certs --secret-file /path/to/encrypted_data_bag_secret
```

The data bag item should contain:

```json
{
  "id": "manager_certs",
  "filebeat_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "filebeat_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "root_ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

Then configure the cookbook to use the data bag:

```json
{
  "override_attributes": {
    "wazuh_manager": {
      "certificates": {
        "data_bag_name": "wazuh_secrets",
        "data_bag_item": "manager_certs"
      }
    }
  }
}
```

#### Alternative: Direct Attribute Configuration

For simpler deployments, you can set credentials directly in attributes (less secure, not recommended for production):

```json
{
  "override_attributes": {
    "wazuh_manager": {
      "indexer": {
        "username": "admin",
        "password": "your_password_here"
      }
    }
  }
}
```

### Recipes

#### manager.rb

Installs the wazuh-manager and required dependencies. Also creates the *local_rules.xml* and *local_decoder.xml* files.

#### common.rb

Generates the ossec.conf file using Gyoku.

#### repository.rb 

Declares wazuh repository and GPG key URIs.

#### prerequisites.rb
Install prerequisites to install Wazuh manager

### References

Check [Wazuh server administration](https://documentation.wazuh.com/current/user-manual/manager/index.html) for more information about Wazuh Server.
