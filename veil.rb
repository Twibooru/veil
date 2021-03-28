# frozen_string_literal: true
require 'cgi'
require 'httparty'
require 'openssl'

class Veil
  DEFAULT_REQUEST_HEADERS = {
    'Via' => 'Veil Asset Proxy',
    'User-Agent' => 'Veil Asset Proxy'
  }.freeze

  DEFAULT_SECURITY_HEADERS = {
    'X-Frame-Options' => 'deny',
    'X-XSS-Protection' => '1; mode=block',
    'X-Content-Type-Options' => 'nosniff',
    'Content-Security-Policy' => "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
  }.freeze

  def initialize(config)
    @config = config

    if @config[:proxy]
      proxy_host, proxy_port = @config[:proxy].split ':'

      HTTParty::Basement.http_proxy(proxy_host, proxy_port.to_i, nil, nil)
    end
  end

  def call(env)
    request = Rack::Request.new env

    return hwhat if !request.get? || request.path == '/'

    provided_digest = request.path.delete_prefix '/'
    provided_url    = request.params['url']

    return four_oh_four('Digest or URL missing') unless provided_digest && provided_url

    provided_url = CGI.unescape(provided_url)
    digest = OpenSSL::HMAC.hexdigest('sha1', @config[:key], provided_url)

    return four_oh_four('Invalid digest') unless provided_digest == digest

    process_url(request, provided_url)
  end

  private

  def process_url(request, url)
    redirects = 0
    response = []

    headers_to_send = {
      'Accept' => request.get_header('Accept') || 'image/*',
      'Accept-Encoding' => request.get_header('Accept-Encoding') || ''
    }.merge(DEFAULT_REQUEST_HEADERS)

    headers_to_return = nil

    HTTParty.get(url, headers: headers_to_send, stream_body: true) do |fragment|
      if [301, 302].include? fragment.code
        redirects += 1
        return four_oh_four('Too many redirects') if redirects > 3
      elsif fragment.code != 200
        return four_oh_four("Bad status code #{fragment.code}")
      end

      # Haven't set the headers yet, only want to do this once.
      if headers_to_return.nil?
        if fragment.http_response['content-length'].to_i > @config[:length_limit]
          return four_oh_four('Content-Length limit exceeded')
        end

        headers_to_return = {
          'Cache-Control' => fragment.http_response['cache-control'] || 'public, max-age=31536000'
        }.merge(DEFAULT_SECURITY_HEADERS)

        %w[content-type etag expires last-modified transfer-encoding content-encoding].each do |h|
          headers_to_return[h] = fragment.http_response[h] if fragment.http_response[h]
        end
      end

      response << fragment
    end

    [200, headers_to_return, response]
  rescue StandardError => e
    four_oh_four "Internal server error: #{e.inspect}"
  end

  def four_oh_four(reason)
    $stderr.puts(reason)

    [404, { 'Content-Type' => 'text/plain' }, ['Not Found']]
  end

  def hwhat
    [200, { 'Content-Type' => 'text/plain' }, ['hwhat']]
  end
end
