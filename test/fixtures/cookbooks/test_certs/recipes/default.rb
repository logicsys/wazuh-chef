# frozen_string_literal: true

# Test fixture to generate self-signed certificates for kitchen testing
# Certificates are generated at COMPILE TIME so attributes are available
# when downstream cookbook recipes compile
#
# Note: OpenSearch requires PKCS#8 format for private keys
# Note: DN must match what's configured in opensearch.yml admin_dn

certs_dir = '/tmp/wazuh-test-certs'

# DN format matching opensearch.yml expectations
# admin_dn: "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
# nodes_dn: "CN=<node_name>,OU=Wazuh,O=Wazuh,L=California,C=US"
admin_subj = '/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh/CN=admin'
indexer_subj = '/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh/CN=wazuh-single-node'
dashboard_subj = '/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh/CN=wazuh-dashboard'
filebeat_subj = '/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh/CN=filebeat'
root_ca_subj = '/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh/CN=root-ca'

# Generate certificates at compile time
ruby_block 'generate_test_certificates_at_compile_time' do
  block do
    require 'fileutils'
    FileUtils.mkdir_p(certs_dir)

    # Generate Root CA
    unless ::File.exist?("#{certs_dir}/root-ca.pem")
      system("openssl genrsa -out #{certs_dir}/root-ca-key-temp.pem 2048 2>/dev/null")
      system("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in #{certs_dir}/root-ca-key-temp.pem -out #{certs_dir}/root-ca-key.pem 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/root-ca-key-temp.pem")
      system("openssl req -new -x509 -sha256 -key #{certs_dir}/root-ca-key.pem -out #{certs_dir}/root-ca.pem -days 3650 -subj '#{root_ca_subj}' 2>/dev/null")
    end

    # Generate Admin certificate
    unless ::File.exist?("#{certs_dir}/admin.pem")
      system("openssl genrsa -out #{certs_dir}/admin-key-temp.pem 2048 2>/dev/null")
      system("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in #{certs_dir}/admin-key-temp.pem -out #{certs_dir}/admin-key.pem 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/admin-key-temp.pem")
      system("openssl req -new -key #{certs_dir}/admin-key.pem -out #{certs_dir}/admin.csr -subj '#{admin_subj}' 2>/dev/null")
      system("openssl x509 -req -in #{certs_dir}/admin.csr -CA #{certs_dir}/root-ca.pem -CAkey #{certs_dir}/root-ca-key.pem -CAcreateserial -out #{certs_dir}/admin.pem -days 3650 -sha256 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/admin.csr")
    end

    # Generate Indexer certificate
    unless ::File.exist?("#{certs_dir}/indexer.pem")
      system("openssl genrsa -out #{certs_dir}/indexer-key-temp.pem 2048 2>/dev/null")
      system("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in #{certs_dir}/indexer-key-temp.pem -out #{certs_dir}/indexer-key.pem 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/indexer-key-temp.pem")
      system("openssl req -new -key #{certs_dir}/indexer-key.pem -out #{certs_dir}/indexer.csr -subj '#{indexer_subj}' 2>/dev/null")
      ::File.write("#{certs_dir}/indexer-ext.cnf", "subjectAltName=DNS:localhost,DNS:wazuh-indexer,DNS:wazuh-single-node,IP:127.0.0.1,IP:0.0.0.0")
      system("openssl x509 -req -in #{certs_dir}/indexer.csr -CA #{certs_dir}/root-ca.pem -CAkey #{certs_dir}/root-ca-key.pem -CAcreateserial -out #{certs_dir}/indexer.pem -days 3650 -sha256 -extfile #{certs_dir}/indexer-ext.cnf 2>/dev/null")
      FileUtils.rm_f(["#{certs_dir}/indexer.csr", "#{certs_dir}/indexer-ext.cnf"])
    end

    # Generate Dashboard certificate
    unless ::File.exist?("#{certs_dir}/dashboard.pem")
      system("openssl genrsa -out #{certs_dir}/dashboard-key-temp.pem 2048 2>/dev/null")
      system("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in #{certs_dir}/dashboard-key-temp.pem -out #{certs_dir}/dashboard-key.pem 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/dashboard-key-temp.pem")
      system("openssl req -new -key #{certs_dir}/dashboard-key.pem -out #{certs_dir}/dashboard.csr -subj '#{dashboard_subj}' 2>/dev/null")
      ::File.write("#{certs_dir}/dashboard-ext.cnf", "subjectAltName=DNS:localhost,DNS:wazuh-dashboard,DNS:wazuh-single-node,IP:127.0.0.1,IP:0.0.0.0")
      system("openssl x509 -req -in #{certs_dir}/dashboard.csr -CA #{certs_dir}/root-ca.pem -CAkey #{certs_dir}/root-ca-key.pem -CAcreateserial -out #{certs_dir}/dashboard.pem -days 3650 -sha256 -extfile #{certs_dir}/dashboard-ext.cnf 2>/dev/null")
      FileUtils.rm_f(["#{certs_dir}/dashboard.csr", "#{certs_dir}/dashboard-ext.cnf"])
    end

    # Generate Filebeat/Manager certificate (used by both manager and filebeat for indexer auth)
    unless ::File.exist?("#{certs_dir}/filebeat.pem")
      system("openssl genrsa -out #{certs_dir}/filebeat-key-temp.pem 2048 2>/dev/null")
      system("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in #{certs_dir}/filebeat-key-temp.pem -out #{certs_dir}/filebeat-key.pem 2>/dev/null")
      FileUtils.rm_f("#{certs_dir}/filebeat-key-temp.pem")
      system("openssl req -new -key #{certs_dir}/filebeat-key.pem -out #{certs_dir}/filebeat.csr -subj '#{filebeat_subj}' 2>/dev/null")
      ::File.write("#{certs_dir}/filebeat-ext.cnf", "subjectAltName=DNS:localhost,DNS:wazuh-manager,DNS:wazuh-single-node,DNS:filebeat,IP:127.0.0.1,IP:0.0.0.0")
      system("openssl x509 -req -in #{certs_dir}/filebeat.csr -CA #{certs_dir}/root-ca.pem -CAkey #{certs_dir}/root-ca-key.pem -CAcreateserial -out #{certs_dir}/filebeat.pem -days 3650 -sha256 -extfile #{certs_dir}/filebeat-ext.cnf 2>/dev/null")
      FileUtils.rm_f(["#{certs_dir}/filebeat.csr", "#{certs_dir}/filebeat-ext.cnf"])
    end

    # Set certificate content in node attributes for downstream cookbooks
    node.override['wazuh_indexer']['certificates']['indexer_pem'] = ::File.read("#{certs_dir}/indexer.pem")
    node.override['wazuh_indexer']['certificates']['indexer_key'] = ::File.read("#{certs_dir}/indexer-key.pem")
    node.override['wazuh_indexer']['certificates']['root_ca_pem'] = ::File.read("#{certs_dir}/root-ca.pem")
    node.override['wazuh_indexer']['certificates']['admin_pem'] = ::File.read("#{certs_dir}/admin.pem")
    node.override['wazuh_indexer']['certificates']['admin_key'] = ::File.read("#{certs_dir}/admin-key.pem")

    node.override['wazuh_dashboard']['certificates']['dashboard_pem'] = ::File.read("#{certs_dir}/dashboard.pem")
    node.override['wazuh_dashboard']['certificates']['dashboard_key'] = ::File.read("#{certs_dir}/dashboard-key.pem")
    node.override['wazuh_dashboard']['certificates']['root_ca_pem'] = ::File.read("#{certs_dir}/root-ca.pem")

    # Set manager certificates (for manager-to-indexer communication)
    node.override['wazuh_manager']['certificates']['filebeat_pem'] = ::File.read("#{certs_dir}/filebeat.pem")
    node.override['wazuh_manager']['certificates']['filebeat_key'] = ::File.read("#{certs_dir}/filebeat-key.pem")
    node.override['wazuh_manager']['certificates']['root_ca_pem'] = ::File.read("#{certs_dir}/root-ca.pem")

    # Set security DN attributes to match our test certificates
    node.override['wazuh_indexer']['security']['admin_dn'] = ['CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US']
    node.override['wazuh_indexer']['security']['nodes_dn'] = ['CN=wazuh-single-node,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US']
  end
  action :nothing
end.run_action(:run)

# Copy filebeat certificates to the filebeat certs directory for filebeat-oss cookbook
directory '/etc/filebeat/certs' do
  owner 'root'
  group 'root'
  mode '0500'
  recursive true
  action :create
end

%w(filebeat.pem filebeat-key.pem root-ca.pem).each do |cert_file|
  file "/etc/filebeat/certs/#{cert_file}" do
    content lazy { ::File.read("#{certs_dir}/#{cert_file}") }
    owner 'root'
    group 'root'
    mode cert_file.include?('key') ? '0400' : '0440'
    action :create
  end
end
