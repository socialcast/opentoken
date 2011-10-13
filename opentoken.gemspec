# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "opentoken/version"

Gem::Specification.new do |s|
  s.name        = "opentoken"
  s.version     = OpenToken::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Ryan Sonnek"]
  s.email       = ["ryan@socialcast.com"]
  s.homepage    = "http://github.com/socialcast/opentoken"
  s.summary     = %q{ruby implementation of the opentoken specification}
  s.description = %q{parse opentoken properties passed for Single Signon requests}

  s.rubyforge_project = "opentoken"

  s.add_runtime_dependency(%q<activesupport>, ["~> 3.0.3"])
  s.add_runtime_dependency(%q<i18n>, [">= 0"])
  s.add_development_dependency(%q<shoulda>, [">= 0"])
  s.add_development_dependency(%q<timecop>, [">= 0.3.4"])

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
