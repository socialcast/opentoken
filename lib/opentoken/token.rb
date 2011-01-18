require 'time'
require 'active_support/hash_with_indifferent_access'
require 'active_support/core_ext/time/calculations'

module OpenToken
  class TokenExpiredError < StandardError;  end

  class Token < ActiveSupport::HashWithIndifferentAccess
    def validate!
      raise OpenToken::TokenExpiredError.new("#{Time.now.utc} is not within token duration: #{self.start_at} - #{self.end_at}") if self.expired?
    end
    #verify that the current time is between the not-before and not-on-or-after values
    def valid?
      start_at.past? && end_at.future?
    end
    def expired?
      !valid?
    end
    def start_at
      payload_date('not-before')
    end
    def end_at
      payload_date('not-on-or-after')
    end
    def valid_until
      payload_date('renew-until')
    end

    private
    def payload_date(key)
      Time.iso8601(self[key])
    end
  end
end