lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'version'

Gem::Specification.new do |spec|
  spec.name = %q{avx_credential_generator}
  spec.version = AVXCredentialGenerator::VERSION
  spec.authors = ['Stefan Patachi']
  spec.email = ['stefan@aion.dk']

  spec.summary = %q{A tool for generating voter credentials in Assembly Voting X election system}
  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'thor', '~> 0.20.3'
  # spec.add_dependency 'charlock_holmes', '~> 0.7.6'
  # spec.add_dependency 'activesupport', '~> 5.2.1'
end
