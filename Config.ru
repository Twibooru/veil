# frozen_string_literal: true

require 'yaml'
require_relative 'veil'

config = {
  key: ENV['VEIL_KEY'],
  proxy: ENV['VEIL_PROXY'],
  length_limit: ENV['VEIL_LENGTH_LIMIT'] || 5242880
}

run Veil.new(config)
