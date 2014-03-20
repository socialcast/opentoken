# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "opentoken/version"

Gem::Specification.new do |s|
  s.name        = "opentoken"
  s.version     = OpenToken::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Socialcast Developers", "Ryan Sonnek"]
  s.email       = ["developers@socialcast.com"]
  s.homepage    = "https://github.com/socialcast/opentoken"
  s.summary     = %q{ruby implementation of the opentoken specification}
  s.description = %q{parse opentoken properties passed for Single Signon requests}
  s.license     = "MIT"
  s.rubyforge_project = "opentoken"

  s.add_runtime_dependency(%q<activesupport>, [">= 3.0.3"])
  s.add_runtime_dependency(%q<i18n>, [">= 0"])
  s.add_development_dependency 'rspec', '>= 2.11'
  s.add_development_dependency 'timecop', '>= 0.7'
  s.add_development_dependency 'rake', '>= 0.9.2.2'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
