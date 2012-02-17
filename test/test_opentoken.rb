require 'helper'

class TestOpentoken < Test::Unit::TestCase
  # OpenToken.debug = true

  #"renew-until"=>"2010-03-05T07:19:15Z"
  #"not-before"=>"2010-03-04T19:19:15Z"
  #"not-on-or-after"=>"2010-03-04T19:24:15Z"
  context "aes-128-cbc token with subject attribute" do
    setup do
      @opentoken = "T1RLAQJ0Ca97sl6MLJAZDa_hdFzMlicMQBDjqUzrXl0EOXKmpj5oo7L5AACgaWoW8fZizrsLbtxb_F00aTdFmhw8flGy4iGqPWPtqYpdIzQZzg5WvrvYH8Rnq7ckJpYk2YPZw6yNyA4ohG-BgFdTHc0U7CwZTFmodg1MuO0cTh7T98s2RXiTcaZa21MNO0yuXKm2Q10cbrWhnB5yHJUhSHx6JLxlgMTZ0oE0DoUOB6JmoLMYHcyL9hKRiPTh62ky_QmXRaifDNOdl4sH2w**"
      @password = 'Test123'
      OpenToken.password = @password
    end
    context "decoding token between expiration dates" do
      setup do
        Timecop.travel(Time.iso8601('2010-03-04T19:20:10Z')) do
          assert_nothing_raised do
            @token = OpenToken.decode @opentoken
          end
        end
      end
      should "decrypt subject from token payload" do
        assert_equal 'john@example.com', @token[:subject]
      end
      should "decrypt subject using string or symbol" do
        assert_equal 'john@example.com', @token['subject']
      end
      should "parse 'renew-until' date" do
        assert_equal Time.iso8601('2010-03-05T07:19:15Z'), @token.valid_until
      end
    end

    context "decoding token when current time is before expiration date" do
      should "raise TokenExpiredError" do
        Timecop.travel(Time.iso8601('2010-03-04T19:19:10Z')) do
          assert_raises OpenToken::TokenExpiredError do
            @token = OpenToken.decode @opentoken
          end
        end
      end
    end

    context "decoding token when current time is equal to expiration date" do
      should "raise TokenExpiredError" do
        Timecop.travel(Time.iso8601('2010-03-04T19:24:15Z')) do
          assert_raises OpenToken::TokenExpiredError do
            @token = OpenToken.decode @opentoken
          end
        end
      end
    end

    context "decoding token with attribute value containing apostrophe" do
      setup do
        Timecop.travel(Time.iso8601('2011-01-13T11:08:01Z')) do
          @opentoken = "T1RLAQLIjiqgexqi1PQcEKCetvGoSYR2jhDFSIfE5ctlSBxEnq3S1ydjAADQUNRIKJx6_14aE3MQZnDABupGJrKNfoJHFS5VOnKexjMtboeOgst31Hf-D9CZBrpB7Jv0KBwnQ7DN3HizecPT76oX3UGtq_Vi5j5bKYCeObYm9W6h7NY-VzcZY5TTqIuulc2Jit381usAWZ2Sv1c_CWwhrH4hw-x7vUQMSjErvXK1qvsrFCpfNr7XlArx0HjI6kT5XEaHgQNdC0zrLw9cZ4rewoEisR3H5oM7B6gMaP82wTSFVBXvpn5r0KT-Iuc3JuG2en1zVh3GNf110oQCKQ**"
          @token = OpenToken.decode @opentoken
        end
      end
      should 'preserve apostrophe in attribute payload' do
        assert_equal "D'angelo", @token[:last_name]
      end
    end

    should 'raise invalid token error parsing nil token' do
      assert_raises OpenToken::TokenInvalidError do
        OpenToken.decode nil
      end
    end
  end

  context "encoding token" do
    setup do
      OpenToken.password = "Password1"
    end
    context "with aes-128-cbc and subject attribute" do
      setup do
          @attributesIn = { "subject" => "john", "email" => "john@example.com"}
          @token = OpenToken.encode @attributesIn, OpenToken::Cipher::AES_128_CBC
      end
      should "be decodable" do
        @attributesOut = OpenToken.decode @token
        assert_equal @attributesIn, @attributesOut
      end
    end
  end

  context "encoding token with utf-8 values" do
    setup do
      OpenToken.password = "Password1"
    end
    context "with aes-128-cbc and subject attribute" do
      setup do
          @subject = "Andr\xC3\xA9".send(:extend, OpenToken::Ext::String).force_encoding('UTF-8')
          @attributesIn = { "subject" => @subject, "email" => "john@example.com"}
          @token = OpenToken.encode @attributesIn, OpenToken::Cipher::AES_128_CBC
      end
      should "be decodable" do
        @attributesOut = OpenToken.decode @token
        assert_equal @attributesIn, @attributesOut
      end
    end
  end
end
