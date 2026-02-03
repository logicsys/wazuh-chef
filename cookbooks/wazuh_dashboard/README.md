# Wazuh Dashboard cookbook

This cookbook installs and configures Wazuh Dashboard on specified nodes.

## Attributes

* `default.rb` contains dashboard configuration including server settings, SSL, API connection, and certificate configuration

Check [Wazuh Dashboard documentation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/index.html) for more information.

## Usage

Create a role, `wazuh_dashboard`. Add attributes as needed to customize the installation.

```json
{
  "name": "wazuh_dashboard",
  "description": "Wazuh Dashboard host",
  "json_class": "Chef::Role",
  "default_attributes": {
  },
  "override_attributes": {
    "wazuh_dashboard": {
      "wazuh_api": {
        "url": "https://192.168.1.10",
        "port": 55000
      }
    }
  },
  "chef_type": "role",
  "run_list": [
    "recipe[wazuh_dashboard::default]"
  ]
}
```

## Data Bags for Passwords and Certificates

This cookbook supports using data bags to securely store sensitive data like the Wazuh API password and certificates.

### Creating an Encrypted Data Bag

First, create or use an existing encryption key:

```bash
# Generate a new encryption key (if you don't have one)
openssl rand -base64 512 | tr -d '\r\n' > /path/to/encrypted_data_bag_secret

# Ensure proper permissions
chmod 600 /path/to/encrypted_data_bag_secret
```

### Wazuh API Password Data Bag

The dashboard connects to the Wazuh API using credentials that can be stored in a data bag. This uses the same `wazuh_secrets` data bag as the manager cookbook.

Create a data bag item (or add to existing `wazuh_secrets` data bag):

```bash
# Create the data bag (skip if already exists from manager setup)
knife data bag create wazuh_secrets

# Create the data bag item with encryption
knife data bag create wazuh_secrets api --secret-file /path/to/encrypted_data_bag_secret
```

The data bag item should contain the password keyed by the API username (default: `wazuh-wui`):

```json
{
  "id": "api",
  "wazuh-wui": "YourSecureApiPassword123!"
}
```

Then configure the cookbook to use the data bag:

```json
{
  "override_attributes": {
    "wazuh_dashboard": {
      "wazuh_api": {
        "data_bag_name": "wazuh_secrets",
        "data_bag_item": "api",
        "data_bag_encrypted": true
      }
    }
  }
}
```

**Note:** The password key in the data bag must match the `wazuh_api.username` attribute. If using a custom username, update both:

```json
{
  "override_attributes": {
    "wazuh_dashboard": {
      "wazuh_api": {
        "username": "custom-api-user",
        "data_bag_name": "wazuh_secrets",
        "data_bag_item": "api",
        "data_bag_encrypted": true
      }
    }
  }
}
```

With data bag:
```json
{
  "id": "api",
  "custom-api-user": "YourSecureApiPassword123!"
}
```

### Certificate Data Bag

To store certificates in the same `wazuh_secrets` data bag:

```bash
knife data bag create wazuh_secrets dashboard_certs --secret-file /path/to/encrypted_data_bag_secret
```

The data bag item should contain:

```json
{
  "id": "dashboard_certs",
  "dashboard_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "dashboard_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "root_ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

Then configure the cookbook to use the data bag:

```json
{
  "override_attributes": {
    "wazuh_dashboard": {
      "certificates": {
        "data_bag_name": "wazuh_secrets",
        "data_bag_item": "dashboard_certs"
      }
    }
  }
}
```

### Alternative: Direct Attribute Configuration

For simpler deployments, you can set credentials directly in attributes (less secure, not recommended for production):

```json
{
  "override_attributes": {
    "wazuh_dashboard": {
      "wazuh_api": {
        "username": "wazuh-wui",
        "password": "your_password_here"
      }
    }
  }
}
```

## Recipes

### default.rb

Includes all required recipes in proper order: repository, certificates, dashboard.

### repository.rb

Declares Wazuh repository and GPG key URIs.

### certificates.rb

Deploys TLS certificates for the dashboard. Certificates can be provided via:
- Direct attributes (PEM content)
- Data bag
- Manual placement

### dashboard.rb

Installs the wazuh-dashboard package, configures `opensearch_dashboards.yml` and `wazuh.yml`, sets up OpenSearch credentials in keystore, and starts the service.

### passwords.rb

Updates the dashboard's OpenSearch connection credentials. Run this after `wazuh_indexer::passwords` to update the dashboard with new indexer passwords.

## References

Check [Wazuh Dashboard documentation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/index.html) for more information about Wazuh Dashboard.
