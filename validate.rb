require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'json_schemer'
end

require 'json'
require 'pathname'

raise 'Usage: ruby script.rb <security schema file name> <report file name>' unless ARGV.size == 2

schema = JSONSchemer.schema(Pathname.new(ARGV[0]))
report = JSON.parse(File.open(ARGV[1]).read)
schema_validation_errors = schema.validate(report).map { |error| JSONSchemer::Errors.pretty(error) }
puts(schema_validation_errors)

