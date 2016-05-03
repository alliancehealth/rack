RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :should }
end

require_relative 'gemloader'
require 'rack'
