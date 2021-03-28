# frozen_string_literal: true

require 'yaml'
require_relative 'veil'

config = {
  via:            ENV.fetch('VEIL_HEADER_VIA', 'Veil Asset Proxy'),
  key:            ENV.fetch('VEIL_KEY'),
  length_limit:   ENV.fetch('VEIL_LENGTH_LIMIT', 5_242_880).to_i,
  max_redirects:  ENV.fetch('VEIL_MAX_REDIRECTS', 4).to_i,
  socket_timeout: ENV.fetch('VEIL_SOCKET_TIMEOUT', 10).to_f,
  proxy:          ENV.fetch('VEIL_PROXY', nil)
}

run Veil.new(config)
