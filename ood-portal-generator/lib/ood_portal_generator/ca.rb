require 'openssl'

module OodPortalGenerator
  # A class to create a user certificate signing CA for application servers
  class CA
    attr_reader :managed, :cert_path, :key_path

    def load
      @key = OpenSSL::PKey.read File.read @key_path, @key_phrase
      @cert = OpenSSL::X509::Certificate.new File.read @cert_path
    end

    def create_ca(name)
      ca_key = OpenSSL::PKey::RSA.new 4096

      FileUtils.mkdir_p File.dirname(@key_path), mode: 0500

      open @key_path, 'w' do |io|
        io.write ca_key.private_to_pem(OpenSSL::Cipher.new('aes-256-cbc'), @key_phrase), perm: 0400
      end

      ca_name = OpenSSL::X509::Name.parse_rfc2253 name

      ca_cert = OpenSSL::X509::Certificate.new
      ca_cert.serial = 0
      ca_cert.version = 2
      ca_cert.not_before = Time.now
      ca_cert.not_after = Time.now + 60 * 60 * 24 * @expire_time

      ca_cert.public_key = ca_key.public_key
      ca_cert.subject = ca_name
      ca_cert.issuer = ca_name

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = ca_cert
      extension_factory.issuer_certificate = ca_cert

      ca_cert.add_extension \
        extension_factory.create_extension('subjectKeyIdentifier', 'hash')
      ca_cert.add_extension \
        extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
      ca_cert.add_extension \
        extension_factory.create_extension(
          'keyUsage', 'cRLSign,keyCertSign', true)

      ca_cert.sign ca_key, OpenSSL::Digest.new('SHA1')
      open @cert_path, 'w' do |io|
        io.write ca_cert.to_pem, perm: 0755
      end
    end

    # @return [Boolean] whether the cert exists
    def exists?
      File.exist?(@cert_path) and File.exist?(@key_path)
    end

    # @return [Boolean] whether the cert expires in the next 45 days
    def expires_soon?
      ca_cert = OpenSSL::X509::Certificate.new File.read @cert_path if self.exists?
      ca_cert.not_after > Time::now + 60 * 60 * 24 * 45
    end
  end

  class UserCA < CA
    def initialize(opts = {})
      opts = {} unless opts.respond_to?(:to_h)
      opts = opts.to_h.each_with_object({}) { |(k, v), h| h[k.to_sym] = v unless v.nil? }

      ca_dir = opts.fetch(:ondemand_user_ca_dir, '/etc/pki/tls/ondemand/user')
      @managed = opts.fetch(:ondemand_user_ca_managed, false)
      @expire_time = opts.fetch(:ondemand_user_ca_duration, 3650)
      @key_phrase = opts.fetch(:ondemand_user_ca_passphrase, 'insecure')

      @cert_path = ca_dir + "/ca.crt"
      @key_path  = ca_dir + "/private/ca.key"
    end
  end

  class OndemandCA < CA

    def initialize(opts = {})
      opts = {} unless opts.respond_to?(:to_h)
      opts = opts.to_h.each_with_object({}) { |(k, v), h| h[k.to_sym] = v unless v.nil? }

      ca_dir = opts.fetch(:ondemand_ca_dir, '/etc/pki/tls/ondemand/infra')
      @managed = opts.fetch(:ondemand_ca_managed, false)
      @expire_time = opts.fetch(:ondemand_ca_duration, 3650)
      @key_phrase = opts.fetch(:ondemand_ca_passphrase, 'insecure')

      @cert_path = ca_dir + "/ca.crt"
      @key_path  = ca_dir + "/private/ca.key"
    end
  end

  class ProxyCert
    attr_reader :ondemand_ca_managed

    # Generate new leaf cert and store
    # @return nil
    def generate
      FileUtils.mkdir_p File.dirname(path), mode: 0500

      @key = OpenSSL::PKey::RSA.new 4096

      # Write the key to disk
      open @key_path, 'w' do |io|
        io.write key.to_pem, perm: 0400
      end
      
      # Write the cert to disk as PEM
      cert = make_cert
      open @cert_path, 'w' do |io|
        io.write cert.to_pem, perm: 0755
      end

      FileUtils.chown OodPortalGenerator.chown_apache_user, OodPortalGenerator.apache_group, [@key_path, @cert_path] # TODO figure out apache user
    end

    # Generate new user certificate and return cert
    # @return nil
    def make_cert
      @root_ca.load

      name = OpenSSL::X509::Name.parse_rfc2253 "CN=Open OnDemand proxy server"
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 0 # We are a non-conforming CA so this doesn't matter
      cert.not_before = Time.now
      cert.not_after = Time.now + 60 * 60 * 24 * 42

      cert.public_key = @key.public_key
      cert.subject = name
      cert.issuer = @root_ca.cert.name

      extension_factory = OpenSSL::X509::ExtensionFactory.new nil, cert
      extension_factory.subject_certificate = cert
      extension_factory.issuer_certificate = @root_ca.cert

      cert.add_extension extension_factory.create_extension('basicConstraints', 'CA:FALSE', true)
      cert.add_extension extension_factory.create_extension(
        'keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
      cert.add_extension extension_factory.create_extension('subjectKeyIdentifier', 'hash')
       
      cert.sign @root_ca.key, OpenSSL::Digest.new('SHA1')

      cert
    end

    def initialize
      opts = {} unless opts.respond_to?(:to_h)
      opts = opts.to_h.each_with_object({}) { |(k, v), h| h[k.to_sym] = v unless v.nil? }

      @managed = opts.fetch(:ondemand_ca_managed, false)
      @cert_path = opts.fetch(:ondemand_client_cert, '/etc/pki/tls/ondemand/client.crt')
      @key_path = opts.fetch(:ondemand_client_cert, '/etc/pki/tls/ondemand/private/client.key')

      @root_ca = OndemandCA.new
    end
  end
end

