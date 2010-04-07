require 'helper'

class TestOpentoken < Test::Unit::TestCase
  #"renew-until"=>"2010-03-05T07:19:15Z"
  #"not-before"=>"2010-03-04T19:19:15Z"
  #"not-on-or-after"=>"2010-03-04T19:24:15Z"
  context "aes-128-cbc token with subject attribute" do
    setup do
      @opentoken = "T1RLAQJ0Ca97sl6MLJAZDa_hdFzMlicMQBDjqUzrXl0EOXKmpj5oo7L5AACgaWoW8fZizrsLbtxb_F00aTdFmhw8flGy4iGqPWPtqYpdIzQZzg5WvrvYH8Rnq7ckJpYk2YPZw6yNyA4ohG-BgFdTHc0U7CwZTFmodg1MuO0cTh7T98s2RXiTcaZa21MNO0yuXKm2Q10cbrWhnB5yHJUhSHx6JLxlgMTZ0oE0DoUOB6JmoLMYHcyL9hKRiPTh62ky_QmXRaifDNOdl4sH2w**"
      @password = 'Test123'
    end
    context "parsing token between expiration dates" do
      setup do
        Timecop.travel(Time.iso8601('2010-03-04T19:20:10Z')) do
          assert_nothing_raised do
            @token = OpenToken.new @opentoken, :password => @password
          end
        end
      end
      should "decrypt subject from token payload" do
        assert_equal 'john@example.com', @token[:subject]
      end
      should "parse 'renew-until' date" do
        assert_equal Time.iso8601('2010-03-05T07:19:15Z'), @token.valid_until
      end
    end

    context "parsing token when current time is before expiration date" do
      should "raise TokenExpiredError" do
        Timecop.travel(Time.iso8601('2010-03-04T19:19:10Z')) do
          assert_raises OpenToken::TokenExpiredError do
            @token = OpenToken.new @opentoken, :password => @password
          end
        end
      end
    end

    context "parsing token when current time is equal to expiration date" do
      should "raise TokenExpiredError" do
        Timecop.travel(Time.iso8601('2010-03-04T19:24:15Z')) do
          assert_raises OpenToken::TokenExpiredError do
            @token = OpenToken.new @opentoken, :password => @password
          end
        end
      end
    end
  end
end
