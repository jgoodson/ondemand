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
      FileUtils.mkdir_p File.dirname(@key_path), mode: 0o500
      FileUtils.chown @user.uid, @user.gid, File.dirname(@key_path)

      @key = OpenSSL::PKey::RSA.new 4096

      # Write the key to disk
      File.open @key_path, "w", 0o400 do |f|
        f.write @key.private_to_pem
      end

      # Write the cert to disk as PEM
      cert = make_cert
      File.open @cert_path, "w", 0o400 do |f|
        f.write cert.to_pem
      end

      FileUtils.chown @user.uid, @user.gid, [File.dirname(@key_path), @key_path, @cert_path]
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
        'keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature'
      )
      cert.add_extension extension_factory.create_extension('subjectKeyIdentifier', 'hash')

      cert.sign @root_ca.key, OpenSSL::Digest.new('SHA1')

      FileUtils.cp(@root_ca.cert_path, @client_ca_path)

      cert
    end

    # @param user [User] the user we want to create a certificate for
    def initialize(user)
      @user = user

      @base_path = "#{NginxStage.pun_tmp_root(user: @user)}/job_certs"
      @cert_path = "#{@base_path}/leaf.crt"
      @key_path = "#{@base_path}/leaf.key"
      @client_ca_path = "#{@base_path}/client_ca.crt"

      @root_ca = UserCA.new(user.name)
      @root_ca.create_ca("CN=#{user.name} CA") unless @root_ca.exists? 
    end
  end

  class CA
    # Root CA Certificate
    # @return [Certificate] the root CA
    attr_reader :cert

    # Root CA Key
    # @return [PKey] the root CA key
    attr_reader :key

    attr_reader :cert_path, :key_path

    def load
      puts @key_phrase
      @key = OpenSSL::PKey.read (File.read @key_path), @key_phrase
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
      ca_cert.not_after = Time.now + 60 * 60 * 24 * 3650

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
    def initialize(user)
      @key_phrase = NginxStage.pun_root_ca_key_phrase
      @cert_path = File.join(NginxStage.pun_root_ca_dir % {user: user}, "user_ca.crt")
      @key_path = File.join(NginxStage.pun_root_ca_dir % {user: user}, "user_ca.key")

      load if exists?
    end
  end
end
