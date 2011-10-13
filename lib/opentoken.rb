require 'base64'
require 'openssl'
require 'digest/sha1'
require 'zlib'
require 'stringio'
require 'cgi'
require 'time'
require File.join(File.dirname(__FILE__), 'opentoken', 'token')
require File.join(File.dirname(__FILE__), 'opentoken', 'key_value_serializer')
require File.join(File.dirname(__FILE__), 'opentoken', 'password_key_generator')

module OpenToken
  class TokenInvalidError < StandardError;  end

  CIPHER_NULL = 0
  CIPHER_AES_256_CBC = 1
  CIPHER_AES_128_CBC = 2
  CIPHER_3DES_168_CBC = 3

  CIPHERS = {
    CIPHER_NULL => {
      :iv_length => 0
    },
    CIPHER_AES_256_CBC => {
      :algorithm => 'aes-256-cbc',
      :iv_length => 32,
      :key_length => 256
    },  
    CIPHER_AES_128_CBC => {
      :algorithm => 'aes-128-cbc',
      :iv_length => 16,
      :key_length => 128
    },
    CIPHER_3DES_168_CBC => {
      :algorithm => 'des-cbc',
      :iv_length => 8,
      :key_length => 168
    }
  }

  class << self
    attr_accessor :debug
    def debug?
      !!debug
    end

    attr_accessor :password
    attr_accessor :token_lifetime
    attr_accessor :renew_until_lifetime

    def encode(attributes, cipherSuite)
      attributes.delete('not-before')
      attributes.delete('not-on-or-after')
      attributes.delete('renew-until')
      attributes.store('not-before', Time.now.utc.iso8601.to_s)
      attributes.store('not-on-or-after', Time.at(Time.now.to_i + token_lifetime).utc.iso8601.to_s)
      attributes.store('renew-until', Time.at(Time.now.to_i + renew_until_lifetime).utc.iso8601.to_s)
      tokenString = ""
      key = OpenToken::PasswordKeyGenerator::generate(password, CIPHERS[cipherSuite])
      c = OpenSSL::Cipher::Cipher::new(CIPHERS[cipherSuite][:algorithm])

      c.encrypt()
      c.key = key
      c.iv = iv = c.random_iv
      serialized = OpenToken::KeyValueSerializer::serialize(attributes)
      compressed = zip_payload serialized
      ivlen = CIPHERS[cipherSuite][:iv_length]
      if ((compressed.length % ivlen) == 0)
        padlen = ivlen
      else
        padlen = ivlen - (compressed.length % ivlen)
      end
      compressed += padlen.chr * padlen
      encrypted = c.update(compressed)
      mac = []
      mac << "0x01".hex.chr # OTK version
      mac << cipherSuite.chr
      mac << iv
      mac << serialized
      hash = OpenSSL::HMAC.digest(OpenToken::PasswordKeyGenerator::SHA1_DIGEST, key, mac.join)
      tokenString = "OTK" + 1.chr + cipherSuite.chr
      tokenString += hash
      tokenString += ivlen.chr
      tokenString += iv
      tokenString += 0.chr # key info length
      tokenString += ((encrypted.length >> 8) &0xFF ).chr
      tokenString += (encrypted.length & 0xFF).chr
      tokenString += encrypted
      inspect_binary_string "Unencoded", tokenString
      encoded = urlsafeBase64Encode tokenString
      inspect_binary_string "Encoded", encoded
      encoded
    end
    def decode(opentoken = nil)
      verify opentoken.present?, 'Unable to parse empty token'
      data = urlsafeBase64Decode(opentoken)
      inspect_binary_string 'DATA', data

      verify_header data
      verify_version data

      #cipher suite identifier
      cipher_suite = char_value_of data[4]
      cipher = CIPHERS[cipher_suite]
      verify !cipher.nil?, "Unknown cipher suite: #{cipher_suite}"

      #SHA-1 HMAC
      payload_hmac = data[5..24]
      inspect_binary_string "PAYLOAD HMAC [5..24]", payload_hmac

      #Initialization Vector (iv)
      iv_length = char_value_of data[25]
      iv_end = char_value_of [26, 26 + iv_length - 1].max
      iv = data[26..iv_end]
      inspect_binary_string "IV [26..#{iv_end}]", iv
      verify iv_length == cipher[:iv_length], "Cipher expects iv length of #{cipher[:iv_length]} and was: #{iv_length}"

      #key (not currently used)
      key_length = char_value_of data[iv_end + 1]
      key_end = iv_end + 1
      verify key_length == 0, "Token key embedding is not currently supported. Key length is: #{key_length}"

      #payload
      payload_length = data[(key_end + 1)..(key_end + 2)].unpack('n').first
      payload_offset = key_end + 3
      encrypted_payload = data[payload_offset..(data.length - 1)]
      verify encrypted_payload.length == payload_length, "Payload length is #{encrypted_payload.length} and was expected to be #{payload_length}"
      inspect_binary_string "ENCRYPTED PAYLOAD [#{payload_offset}..#{data.length - 1}]", encrypted_payload

      key = OpenToken::PasswordKeyGenerator.generate(password, cipher)
      inspect_binary_string 'KEY', key

      compressed_payload = decrypt_payload(encrypted_payload, cipher, key, iv)
      inspect_binary_string 'COMPRESSED PAYLOAD', compressed_payload

      unparsed_payload = unzip_payload compressed_payload
      puts 'EXPANDED PAYLOAD', unparsed_payload if debug?

      #validate payload hmac
      mac = []
      mac << "0x01".hex.chr
      mac << cipher_suite.chr
      mac << iv
      mac << key if key_length > 0 #key embedding is not currently supported
      mac << unparsed_payload
      hash = OpenSSL::HMAC.digest(OpenToken::PasswordKeyGenerator::SHA1_DIGEST, key, mac.join)
      if (hash <=> payload_hmac) != 0
        verify payload_hmac == hash, "HMAC for payload was #{hash} and expected to be #{payload_hmac}"
      end

      unescaped_payload = CGI::unescapeHTML(unparsed_payload)
      puts 'UNESCAPED PAYLOAD', unescaped_payload if debug?
      token = OpenToken::KeyValueSerializer.deserialize unescaped_payload
      puts token.inspect if debug?
      token.validate!
      token
    end

    private
    def char_value_of(character)
      if RUBY_VERSION < "1.9"
        return character
      else
        return character.chr.ord
      end
    end
    def verify_header(data)
      header = data[0..2]
      verify header == 'OTK', "Invalid token header: #{header}"
    end
    def verify_version(data)
      version = char_value_of data[3]
      verify version == 1, "Unsupported token version: '#{version}'"
    end
    #ruby 1.9 has Base64.urlsafe_decode64 which can be used instead of gsubbing '_' and '-'
    def urlsafeBase64Decode(token)
      string = token.gsub('*', '=').gsub('_', '/').gsub('-', '+')
      data = Base64.decode64(string)
    end
    def urlsafeBase64Encode(token)
      string = Base64.encode64(token);
      string = string.gsub('=', '*').gsub('/', '_').gsub('+', '-').gsub(10.chr, '').gsub(11.chr, '')
      string
    end
    def verify(assertion, message = 'Invalid Token')
      raise OpenToken::TokenInvalidError.new(message) unless assertion
    end
    #see http://snippets.dzone.com/posts/show/4975
    #see http://jdwyah.blogspot.com/2009/12/decrypting-ruby-aes-encryption.html
    #see http://snippets.dzone.com/posts/show/576
    def decrypt_payload(encrypted_payload, cipher, key, iv)
      return encrypted_payload unless cipher[:algorithm]
      crypt = OpenSSL::Cipher::Cipher.new(cipher[:algorithm])
      crypt.decrypt
      crypt.key = key 
      crypt.iv = iv
      crypt.update(encrypted_payload) + crypt.final
    end
    #decompress the payload
    #see http://stackoverflow.com/questions/1361892/how-to-decompress-gzip-data-in-ruby
    def unzip_payload(compressed_payload)
      unparsed_payload = begin
        Zlib::Inflate.inflate(compressed_payload)
      rescue Zlib::BufError
        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(compressed_payload[2, compressed_payload.size])
      end
    end
    def zip_payload(uncompressed)
      compressed = Zlib::Deflate.deflate(uncompressed, 9)
      compressed
    end
    def inspect_binary_string(header, string)
      return unless debug?
      puts "#{header}:"
      index = 0
      string.each_byte do |b| 
        puts "#{index}: #{b} => #{b.chr}" 
        index += 1 
      end
    end
  end
end

# intialize defaults
OpenToken.token_lifetime = 300
OpenToken.renew_until_lifetime = 43200
