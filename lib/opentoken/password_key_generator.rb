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
