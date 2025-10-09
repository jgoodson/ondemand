require 'openssl'

module NginxStage
  # A class to handle generating storing and retrieving user X509 certificate
  class UserCertificate
    # Path of the per-user leaf certificate
    # @return [String] the path of the certificate file
    attr_reader :cert_path

    # Path of the per-user leaf certificate key file
    # @return [String] the path of the certificate key file
    attr_reader :key_path

    # Generate new leaf cert and store
    # @return nil
    def generate
      FileUtils.mkdir_p File.dirname(@key_path), mode: 0500

      @key = OpenSSL::PKey::RSA.new 4096

      # Write the key to disk
      open @key_path, 'w' do |io|
        io.write @key.to_pem, perm: 0400
      end
      # TODO chown
      
      # Write the cert to disk as PEM
      cert = make_cert
      open @cert_path, 'w' do |io|
        io.write cert.to_pem, perm: 0400
      end

      FileUtils.chown @user.uid, @user.gid, [@key_path, @cert_path] 
    end

    # Generate new user certificate and return cert
    # @return nil
    def make_cert

      name = OpenSSL::X509::Name.parse "/CN=#{@user}/DC=#{@user}"
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 0 # We are a non-conforming CA so this doesn't matter
      cert.not_before = Time.now
      cert.not_after = Time.now + 60 * 60 * 24 * 42

      cert.public_key = @key.public_key
      cert.subject = name
      cert.issuer = @root_ca.cert.subject

      extension_factory = OpenSSL::X509::ExtensionFactory.new nil, cert
      extension_factory.subject_certificate = cert
      extension_factory.issuer_certificate = @root_ca.cert

      cert.add_extension extension_factory.create_extension('basicConstraints', 'CA:FALSE', true)
      cert.add_extension extension_factory.create_extension(
        'keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
      cert.add_extension extension_factory.create_extension('subjectKeyIdentifier', 'hash')
       
      cert.sign @root_ca.key, OpenSSL::Digest.new('SHA1')

      client_ca = NginxStage.pun_client_ca_path

      FileUtils.cp(client_ca, @client_ca_path) unless File.file?(@client_ca_path) or !File.file?(client_ca)

      cert
    end

    # @return [Boolean] whether the cert will expire in the next 30 days
    def expires_soon?
      cert = OpenSSL::X509::Certificate.new File.read @cert_path
      cert.not_after < Time.now + 60 * 60 * 24 * 30
    end

    # @return [Boolean] whether the cert exists and is valid for one month
    def valid?
      File.file?(cert_path) and File.file?(key_path) and !expires_soon?
    end

    # @param user [User] the user we want to create a certificate for
    def initialize(user)
      @user = user

      @base_path = NginxStage.pun_tmp_root(user: @user) + "/job_certs/"
      @cert_path = @base_path + "leaf.crt"
      @key_path = @base_path + "leaf.key"
      @client_ca_path = @base_path + "client_ca.crt"

      @root_ca = RootCA.new
    end
  end

  class RootCA
    # Root CA Certificate
    # @return [Certificate] the root CA
    attr_reader :cert

    # Root CA Key
    # @return [PKey] the root CA key
    attr_reader :key

    def initialize
      cert_path = NginxStage.pun_root_ca_cert_path
      key_path = NginxStage.pun_root_ca_key_path
      key_phrase = NginxStage.pun_root_ca_key_phrase

      @key = OpenSSL::PKey.read File.read(key_path), key_phrase
      @cert = OpenSSL::X509::Certificate.new File.read cert_path
    end
  end
end
