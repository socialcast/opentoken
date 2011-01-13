require 'base64'
require 'openssl'
require 'digest/sha1'
require 'zlib'
require 'stringio'
require 'cgi'

class OpenToken
  class TokenExpiredError < StandardError;  end

  DEBUG = false
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

  def initialize(token, options = {})
    #ruby 1.9 has Base64.urlsafe_decode64 which can be used instead of gsubbing '_' and '-'
    string = (token || '').gsub('*', '=').gsub('_', '/').gsub('-', '+')
    data = Base64.decode64(string)
    inspect_binary_string 'DATA', data

    #header: should be OTK
    header = data[0..2]
    raise "Invalid token header: #{header}" unless header == 'OTK'

    #version: should == 1
    version = data[3]
    raise "Unsupported token version: #{version}" unless version == 1

    #cipher suite identifier
    cipher_suite = data[4]
    cipher = CIPHERS[cipher_suite]
    raise "Unknown cipher suite: #{cipher_suite}" if cipher.nil?

    #SHA-1 HMAC
    payload_hmac = data[5..24]
    inspect_binary_string "PAYLOAD HMAC [5..24]", payload_hmac

    #Initialization Vector (iv)
    iv_length = data[25]
    iv_end = [26, 26 + iv_length - 1].max
    iv = data[26..iv_end]
    inspect_binary_string "IV [26..#{iv_end}]", iv
    raise "Cipher expects iv length of #{cipher[:iv_length]} and was: #{iv_length}" unless iv_length == cipher[:iv_length]

    #key (not currently used)
    key_length = data[iv_end + 1]
    key_end = iv_end + 1
    raise "Token key embedding is not currently supported" unless key_length == 0

    #payload
    payload_length = data[(key_end + 1)..(key_end + 2)].unpack('n').first
    payload_offset = key_end + 3
    encrypted_payload = data[payload_offset..(data.length - 1)]
    raise "Payload length is #{encrypted_payload.length} and was expected to be #{payload_length}" unless encrypted_payload.length == payload_length
    inspect_binary_string "ENCRYPTED PAYLOAD [#{payload_offset}..#{data.length - 1}]", encrypted_payload

    key = PasswordKeyGenerator.generate(options[:password], cipher)
    inspect_binary_string 'KEY', key

    compressed_payload = decrypt_payload(encrypted_payload, cipher, key, iv)
    inspect_binary_string 'COMPRESSED PAYLOAD', compressed_payload

    #decompress the payload
    #see http://stackoverflow.com/questions/1361892/how-to-decompress-gzip-data-in-ruby
    unparsed_payload = begin
      Zlib::Inflate.inflate(compressed_payload)
    rescue Zlib::BufError
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(compressed_payload[2, compressed_payload.size])
    end
    puts 'EXPANDED PAYLOAD', unparsed_payload if DEBUG

    #validate payload hmac
    mac = "0x01".hex.chr
    mac += cipher_suite.chr
    mac += iv
    mac += key if key_length > 0 #key embedding is not currently supported
    mac += unparsed_payload
    hash = OpenSSL::HMAC.digest(PasswordKeyGenerator::SHA1_DIGEST, key, mac)
    if (hash <=> payload_hmac) != 0
      raise "HMAC for payload was #{hash} and expected to be #{payload_hmac}" unless payload_hmac == hash
    end

    unescaped_payload = CGI::unescapeHTML(unparsed_payload)
    puts 'UNESCAPED PAYLOAD', unescaped_payload if DEBUG
    @payload = KeyValueSerializer.deserialize unescaped_payload
    puts @payload.inspect if DEBUG
    raise TokenExpiredError.new("#{Time.now.utc} is not within token duration: #{self.start_at} - #{self.end_at}") if self.expired?
  end

  def [](key)
    @payload[key.to_s]
  end
  #verify that the current time is between the not-before and not-on-or-after values
  def expired?
    now = Time.now.utc
    now < start_at || now >= end_at
  end
  def start_at
    payload_date('not-before')
  end
  def end_at
    payload_date('not-on-or-after')
  end
  #"renew-until"=>"2010-03-05T07:19:15Z"
  def valid_until
    payload_date('renew-until')
  end
  def payload_date(key)
    Time.iso8601(self[key]).utc
  end

  private
  def decrypt_payload(encrypted_payload, cipher, key, iv)
    return encrypted_payload unless cipher[:algorithm]
    #see http://snippets.dzone.com/posts/show/4975
    #see http://jdwyah.blogspot.com/2009/12/decrypting-ruby-aes-encryption.html
    #see http://snippets.dzone.com/posts/show/576
    crypt = OpenSSL::Cipher::Cipher.new(cipher[:algorithm])
    crypt.decrypt
    crypt.key = key 
    crypt.iv = iv
    crypt.update(encrypted_payload) + crypt.final
  end

  def inspect_binary_string(header, string)
    return unless DEBUG
    puts "#{header}:"
    index = 0
    string.each_byte do |b| 
      puts "#{index}: #{b} => #{b.chr}" 
      index += 1 
    end
  end
end

class PasswordKeyGenerator
  SHA1_DIGEST = OpenSSL::Digest::Digest.new('sha1')

  def self.generate(password, cipher_suite)
    salt = 0.chr * 8
    self.generate_impl(password, cipher_suite, salt, 1000)
  end

  def self.generate_block(password, salt, count, index)
    mac = salt
    mac += [index].pack("N")
    
    result = OpenSSL::HMAC.digest(SHA1_DIGEST, password, mac)
    cur = result
    
    i_count = 1
    while i_count < count
      i_count +=1
      
      cur = OpenSSL::HMAC.digest(SHA1_DIGEST, password, cur)
      
      20.times do |i|
        result[i] = result[i] ^ cur[i]
      end
    end

    return result
  end
  
  def self.generate_impl(password, cipher, salt, iterations)
    return unless cipher[:algorithm]

    key_size = cipher[:key_length] / 8
    numblocks = key_size / 20
    numblocks += 1 if (key_size % 20) > 0
    
    # Generate the appropriate number of blocks and write their output to
    # the key bytes; note that it's important to start from 1 (vs. 0) as the
    # initial block number affects the hash. It's not clear that this fact
    # is stated explicitly anywhere, but without this approach, the generated
    # keys will not match up with test cases defined in RFC 3962.
    key_buffer_index = 0
    key = ""
    
    numblocks.times do |i|
      i+=1 # Previously zero based, needs to be 1 based
      block = self.generate_block(password, salt, iterations, i)
      len = [20, (key_size - key_buffer_index)].min
      key += block[0, len]
      key_buffer_index += len
    end
    
    return key
  end
end

class KeyValueSerializer
  LINE_START = 0
  EMPTY_SPACE = 1
  VALUE_START = 2
  LINE_END = 3
  IN_KEY = 4
  IN_VALUE = 5
  IN_QUOTED_VALUE = 6

  def self.unescape_value(value)
    value.gsub("\\\"", "\"").gsub("\\\'", "'")
  end

  def self.deserialize(string)
    result = {}
    state = LINE_START
    open_quote_char = 0.chr
    currkey = ""
    token = ""
    nextval = ""
    
    string.split(//).each do |c|
      nextval = c

      case c
      when "\t"
        if state == IN_KEY
          # key ends
          currkey = token
          token = ""
          state = EMPTY_SPACE
        elsif state == IN_VALUE
          # non-quoted value ends
          result[currkey] = self.deserialize(token)
          token = ""
          state = LINE_END
        elsif state == IN_QUOTED_VALUE
          token += c
        end
      when " "
        if state == IN_KEY
          # key ends
          currkey = token
          token = ""
          state = EMPTY_SPACE
        elsif state == IN_VALUE
          # non-quoted value ends
          result[currkey] = self.deserialize(token)
          token = ""
          state = LINE_END
        elsif state == IN_QUOTED_VALUE
          token += c
        end
      when "\n"
        # newline
        if (state == IN_VALUE) || (state == VALUE_START)
          result[currkey] = self.unescape_value(token)
          token = ""
          state = LINE_START
        elsif state == LINE_END
          token = ""
          state = LINE_START
        elsif state == IN_QUOTED_VALUE
          token += c
        end
      when "="
        if state == IN_KEY
          currkey = token
          token = ""
          state = VALUE_START
        elsif (state == IN_QUOTED_VALUE) || (state == IN_VALUE)
          token += c
        end
      when "\""
        if state == IN_QUOTED_VALUE
          if (c == open_quote_char) && (token[token.size-1] != "\\"[0])
            result[currkey] = self.unescape_value(token)
            token = ""
            state = LINE_END
          else
            token += c
          end
        elsif state == VALUE_START
          state = IN_QUOTED_VALUE
          open_quote_char = c
        end
      when "'"
        if state == IN_QUOTED_VALUE
          if (c == open_quote_char) && (token[token.size-1] != "\\"[0])
            result[currkey] = self.unescape_value(token)
            token = ""
            state = LINE_END
          else
            token += c
          end
        else state == VALUE_START
          state = IN_QUOTED_VALUE
          open_quote_char = c
        end
      else
        if state == LINE_START
          state = IN_KEY
        elsif state == VALUE_START
          state = IN_VALUE
        end
        token += c
      end
      
      if (state == IN_QUOTED_VALUE) || (state == IN_VALUE)
        result[currkey] = unescape_value(token)
      end
    end
    result
  end
end
