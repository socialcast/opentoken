module OpenToken
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
      result = OpenToken::Token.new
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
end