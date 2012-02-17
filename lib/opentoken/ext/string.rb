module OpenToken::Ext
  module String
    def force_encoding(enc)
      if RUBY_VERSION =~ /1.9.*/
        super
      else
        self
      end
    end
  end
end

