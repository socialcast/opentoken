require 'openssl'

module OpenToken
  class Cipher
    class InvalidCipherError < StandardError;  end

    attr_reader :algorithm
    attr_reader :iv_length
    attr_reader :key_length
    attr_reader :suite

    def initialize(attrs = {})
      @suite = attrs[:suite]
      @iv_length = attrs[:iv_length]
      @key_length = attrs[:key_length]
      @algorithm = attrs[:algorithm]
    end
    def self.for_suite(cipher_suite)
      cipher = REGISTERED_CIPHERS.detect {|c| c.suite == cipher_suite }
      raise InvalidCipherError.new("Unknown cipher suite: #{cipher_suite}") unless cipher
      cipher
    end

    def generate_key
      OpenToken::PasswordKeyGenerator.generate OpenToken.password, self
    end
    def generate_iv
      OpenSSL::Random.random_bytes(iv_length)
    end

    #see http://snippets.dzone.com/posts/show/4975
    #see http://jdwyah.blogspot.com/2009/12/decrypting-ruby-aes-encryption.html
    #see http://snippets.dzone.com/posts/show/576
    def decrypt_payload(encrypted_payload, key, iv)
      return encrypted_payload unless algorithm
      c = crypt :decrypt, key, iv
      c.update(encrypted_payload) + c.final
    end
    def encrypt_payload(payload, key, iv)
      c = crypt :encrypt, key, iv
      padding = if payload.length % iv_length == 0
        iv_length
      else
        iv_length - (payload.length % iv_length)
      end
      c.update(payload + (padding.chr * padding))
    end

    private
    def crypt(operation, key, iv)
      crypt = OpenSSL::Cipher::Cipher.new(algorithm)
      crypt.send operation
      crypt.key = key 
      crypt.iv = iv
      crypt
    end

    NULL = Cipher.new(:suite => 0, :iv_length => 0)
    AES_256_CBC = Cipher.new(:suite => 1, :iv_length => 32, :key_length => 256, :algorithm => 'aes-256-cbc')
    AES_128_CBC = Cipher.new(:suite => 2, :iv_length => 16, :key_length => 128, :algorithm => 'aes-128-cbc')
    DES3_168_CBC = Cipher.new(:suite => 3, :iv_length => 8, :key_length => 168, :algorithm => 'des-cbc')

    REGISTERED_CIPHERS = []
    REGISTERED_CIPHERS << NULL
    REGISTERED_CIPHERS << AES_256_CBC
    REGISTERED_CIPHERS << AES_128_CBC
    REGISTERED_CIPHERS << DES3_168_CBC
  end
end
