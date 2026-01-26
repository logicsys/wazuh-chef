# Cookbook:: filebeat-oss
# Attribute:: filebeat.yml
# Author:: Wazuh <info@wazuh.com>

# Indexer connection credentials (stored in Filebeat keystore)
# These should be overridden in your environment/role with actual credentials
default['filebeat']['indexer_username'] = 'admin'
default['filebeat']['indexer_password'] = 'admin'

default['filebeat']['yml'] = {
    'output' => {
        'elasticsearch' => {
            'hosts' => [
                {
                    'ip' => '127.0.0.1',
                    'port' => 9200,
                },
            ],
        },
    },
}
