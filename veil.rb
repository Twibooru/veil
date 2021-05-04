# frozen_string_literal: true
require 'cgi'
require 'date'
require 'http'
require 'openssl'
require 'addressable/uri'

require_relative 'http_ext'

class Veil
  # Default security-related headers that are sent in responses to the client.
  DEFAULT_SECURITY_HEADERS = {
    'X-Frame-Options' => 'deny',
    'X-XSS-Protection' => '1; mode=block',
    'X-Content-Type-Options' => 'nosniff',
    'Content-Security-Policy' => "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
  }.freeze

  # Header names that are copied from the upstream response to the client response, if present.
  PASSTHROUGH_HEADERS = %w[content-type etag expires last-modified transfer-encoding content-encoding].freeze

  # Response that's sent to the client for a 404 or other error
  FOUR_OH_FOUR_RESPONSE = [
    404,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain', 'Cache-Control' => 'no-cache, no-store, private, must-revalidate' }).freeze,
    ['Not Found'].freeze
  ].freeze

  # Response that's sent for a GET to /, or non-GET requests
  INDEX_RESPONSE = [
    200,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain' }).freeze,
    ['hwhat'].freeze
  ].freeze

  # Response that's sent for a GET to /favicon.ico. Unsure why this is a thing, but Camo did it.
  FAVICON_RESPONSE = [
    200,
    DEFAULT_SECURITY_HEADERS.merge({ 'Content-Type' => 'text/plain' }).freeze,
    ['ok'].freeze
  ].freeze

  def initialize(config)
    @config = config
    @mime_type_whitelist = File.readlines('mime_types', chomp: true)

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
    response = perform_upstream_request request, url

    return four_oh_four("Bad status code #{response.status}") unless response.status.success?

    mime_type = response['content-type'].split(';')[0].downcase

    return four_oh_four("Bad response MIME type #{mime_type}") unless @mime_type_whitelist.include? mime_type

    content_to_return = []
    headers_to_return = {
      'Cache-Control' => response['cache-control'] || 'public, max-age=31536000'
    }.merge(DEFAULT_SECURITY_HEADERS)

    PASSTHROUGH_HEADERS.each do |h|
      headers_to_return[h] = response[h] if response[h]
    end

    content_length = 0

    # Keep reading chunks of the upstream response until the end, bailing out if we read more than the limit.
    response.stream_body do |chunk| # see http_ext.rb
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

  # request = the Rack request from the client
  def perform_upstream_request(request, url)
    headers_to_send = {
      'Via' => @config[:via],
      'User-Agent' => @config[:via],
      'Accept' => request.get_header('Accept') || 'image/*',
      'Accept-Encoding' => request.get_header('Accept-Encoding') || ''
    }

    http_client.timeout(@config[:socket_timeout])
               .headers(headers_to_send)
               .follow(max_hops: @config[:max_redirects])
               .get(url)
  end

  def four_oh_four(reason)
    $stderr.puts("[#{DateTime.now}] #{reason}") if @config[:logging] == 'error'

    FOUR_OH_FOUR_RESPONSE
  end

  def http_client
    (@proxy ? HTTP.via(*@proxy) : HTTP)
  end
end
