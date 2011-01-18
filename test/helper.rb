require 'bundler'
Bundler.require :default, :development

require 'test/unit'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'opentoken'

class Test::Unit::TestCase
end
