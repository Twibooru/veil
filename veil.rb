# frozen_string_literal: true
require 'cgi'
require 'http'
require 'openssl'
require 'addressable/uri'

class Veil
  DEFAULT_SECURITY_HEADERS = {
    'X-Frame-Options' => 'deny',
    'X-XSS-Protection' => '1; mode=block',
    'X-Content-Type-Options' => 'nosniff',
    'Content-Security-Policy' => "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
  }.freeze

  FOUR_OH_FOUR_RESPONSE = [
    404,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain', 'Cache-Control' => 'no-cache, no-store, private, must-revalidate' }).freeze,
    ['Not Found'].freeze
  ].freeze

  INDEX_RESPONSE = [
    200,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain' }).freeze,
    ['hwhat'].freeze
  ].freeze

  FAVICON_RESPONSE = [
    200,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain' }).freeze,
    ['ok'].freeze
  ].freeze

  def initialize(config)
    @config = config

    if @config[:proxy]
      proxy_uri = Addressable::URI.parse @config[:proxy]
      default_port = proxy_uri.scheme == 'https' ? 443 : 80

      @proxy = [proxy_uri.host, proxy_uri.port || default_port, proxy_uri.user, proxy_uri.password]
    end
  end

  def call(env)
    request = Rack::Request.new env

    return INDEX_RESPONSE   if !request.get? || request.path == '/'
    return FAVICON_RESPONSE if request.path == '/favicon.ico'

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
    headers_to_send = {
      'Via' => @config[:via],
      'User-Agent' => @config[:via],
      'Accept' => request.get_header('Accept') || 'image/*',
      'Accept-Encoding' => request.get_header('Accept-Encoding') || ''
    }

    response = http_client.timeout(@config[:socket_timeout])
                          .headers(headers_to_send)
                          .follow(max_hops: @config[:max_redirects])
                          .get(url)

    return four_oh_four("Bad status code #{response.status}") unless response.status.success?

    content_to_return = []
    headers_to_return = {
      'Cache-Control' => response['cache-control'] || 'public, max-age=31536000'
    }.merge(DEFAULT_SECURITY_HEADERS)

    %w[content-type etag expires last-modified transfer-encoding content-encoding].each do |h|
      headers_to_return[h] = response[h] if response[h]
    end

    content_length = 0

    loop do
      chunk = response.body.readpartial
      break if chunk.nil?

      content_length += chunk.length

      return four_oh_four('Content-Length limit exceeded') if content_length > @config[:length_limit]

      content_to_return << chunk
    end

    [200, headers_to_return, content_to_return]
  rescue HTTP::Redirector::TooManyRedirectsError => e
    four_oh_four "Too many redirects: #{e.inspect}"
  rescue HTTP::TimeoutError => e
    four_oh_four "Timed out: #{e.inspect}"
  rescue StandardError => e
    four_oh_four "Internal server error: #{e.inspect}"
  end

  def four_oh_four(reason)
    $stderr.puts(reason)

    FOUR_OH_FOUR_RESPONSE
  end

  def favicon
    [200, {  }, ['ok']]
  end

  def http_client
    (@proxy ? HTTP.via(*@proxy) : HTTP)
  end
end
