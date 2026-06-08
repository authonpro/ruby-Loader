# frozen_string_literal: true

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Authon Ruby SDK — Software Licensing & Authentication                     ║
# ║  Version: 1.0.0                                                            ║
# ║  Dependencies: None (net/http stdlib)                                      ║
# ║                                                                            ║
# ║  Website: https://authon.pro                                               ║
# ║  Docs:    https://authon.pro/docs                                          ║
# ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
# ║  Status:  https://authon.pro/status                                        ║
# ║  Health:  https://api.authon.pro/health                                    ║
# ║  GitHub:  https://github.com/authonpro                                     ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    require_relative 'authon'                                               ║
# ║    auth = Authon::Client.new('app-id', 'api-key')                          ║
# ║    auth.init!                                                              ║
# ║    result = auth.login('user', 'pass')                                     ║
# ║    puts "Welcome #{auth.username}!" if result[:success]                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

require 'net/http'
require 'uri'
require 'json'
require 'digest'
require 'open3'

module Authon
  # SDK version string.
  VERSION = '1.0.0'

  # Default API endpoint URL.
  DEFAULT_API_URL = 'https://api.authon.pro/v1'

  # Default HTTP timeout in seconds.
  DEFAULT_TIMEOUT = 15

  # Custom error class for Authon SDK errors.
  class AuthonError < StandardError
    attr_reader :code

    def initialize(message, code = nil)
      @code = code
      super(message)
    end
  end

  # Main client for the Authon authentication and licensing API.
  #
  # Provides methods for application initialization, user authentication,
  # session management, variable storage, file downloads, and activity logging.
  #
  # @example Basic usage
  #   auth = Authon::Client.new('app-id', 'api-key')
  #   auth.init!
  #   result = auth.login('username', 'password')
  #   if result[:success]
  #     puts "Welcome #{auth.username}! Level: #{auth.level}"
  #   end
  #
  class Client
    # Session state attributes
    attr_reader :session_token, :username, :level, :subscription, :expires_at

    # App info attributes (populated after init)
    attr_reader :app_name, :app_version, :hwid_lock, :hash_check, :initialized

    # Creates a new Authon client instance.
    #
    # @param app_id [String] Your Application ID from the Authon dashboard.
    # @param api_key [String] Your API Key from the Authon dashboard.
    # @param api_url [String] Custom API URL (default: https://api.authon.pro/v1).
    # @raise [ArgumentError] If app_id or api_key is empty.
    def initialize(app_id, api_key, api_url: DEFAULT_API_URL)
      raise ArgumentError, 'app_id is required' if app_id.nil? || app_id.strip.empty?
      raise ArgumentError, 'api_key is required' if api_key.nil? || api_key.strip.empty?

      @app_id = app_id.strip
      @api_key = api_key.strip
      @api_url = api_url.chomp('/')

      # Session state
      @session_token = nil
      @username = nil
      @level = 0
      @subscription = nil
      @expires_at = nil

      # App info
      @app_name = nil
      @app_version = nil
      @hwid_lock = false
      @hash_check = false
      @initialized = false
    end

    # Returns true if the client has an active session.
    #
    # @return [Boolean]
    def authenticated?
      !@session_token.nil? && !@session_token.empty?
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # HWID GENERATION
    # ═══════════════════════════════════════════════════════════════════════════

    # Generates a hardware ID unique to the current machine.
    #
    # Windows: Uses disk serial number + computer name.
    # Linux:   Uses /etc/machine-id.
    # macOS:   Uses system_profiler hardware UUID.
    #
    # @return [String] 32-character lowercase hex MD5 hash.
    def self.get_hwid
      raw = ''

      case RUBY_PLATFORM
      when /mswin|mingw|cygwin/
        # Windows
        begin
          output, = Open3.capture2('wmic diskdrive get serialnumber')
          lines = output.split("\n")
          raw = lines[1]&.strip || ''
        rescue StandardError
          raw = ''
        end
        raw += Socket.gethostname rescue ENV['COMPUTERNAME'] || ''
      when /darwin/
        # macOS
        begin
          output, = Open3.capture2('system_profiler SPHardwareDataType')
          output.each_line do |line|
            if line.include?('UUID')
              raw = line.split(':')[1]&.strip || ''
              break
            end
          end
        rescue StandardError
          raw = ''
        end
        raw = "#{Socket.gethostname}#{RUBY_PLATFORM}" if raw.empty?
      else
        # Linux
        if File.exist?('/etc/machine-id')
          raw = File.read('/etc/machine-id').strip
        else
          raw = "#{Socket.gethostname rescue 'unknown'}#{RUBY_PLATFORM}"
        end
      end

      raw = "fallback-#{Socket.gethostname rescue 'ruby'}" if raw.empty?
      Digest::MD5.hexdigest(raw)
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # INITIALIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    # Initializes the connection to the Authon API.
    # Must be called before any other API method.
    #
    # @return [Hash] Response with :success, :message, :data keys.
    def init!
      result = request(type: 'init')

      if result[:success]
        data = result[:data] || {}
        @app_name = data['name']
        @app_version = data['version']
        @hwid_lock = data['hwidLock'] || false
        @hash_check = data['hashCheck'] || false
        @initialized = true
      end

      result
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION
    # ═══════════════════════════════════════════════════════════════════════════

    # Authenticates with username and password.
    #
    # On success, sets session_token, username, level, subscription, expires_at.
    #
    # @param username [String] User's username.
    # @param password [String] User's password.
    # @param hwid [String, nil] Hardware ID (nil to auto-generate).
    # @return [Hash] Response hash.
    #
    # Possible error messages:
    # - "Invalid credentials"
    # - "Account banned"
    # - "Hardware ID mismatch"
    # - "Subscription expired"
    # - "Account is frozen"
    # - "VPN/Proxy connections are not allowed"
    def login(username, password, hwid: nil)
      if username.nil? || username.strip.empty? || password.nil? || password.strip.empty?
        return { success: false, message: 'Username and password are required' }
      end

      result = request(
        type: 'login',
        username: username,
        password: password,
        hwid: hwid || self.class.get_hwid
      )

      extract_session(result[:data]) if result[:success]
      result
    end

    # Authenticates using a license key only.
    #
    # @param license_key [String] The license key.
    # @param hwid [String, nil] Hardware ID (nil to auto-generate).
    # @return [Hash] Response hash.
    def license(license_key, hwid: nil)
      if license_key.nil? || license_key.strip.empty?
        return { success: false, message: 'License key is required' }
      end

      result = request(
        type: 'license',
        licenseKey: license_key,
        hwid: hwid || self.class.get_hwid
      )

      extract_session(result[:data]) if result[:success]
      result
    end

    # Registers a new user account with a license key.
    #
    # @param username [String] Desired username.
    # @param password [String] Desired password.
    # @param license_key [String] A valid, unused license key.
    # @param hwid [String, nil] Hardware ID (nil to auto-generate).
    # @return [Hash] Response hash.
    def register(username, password, license_key, hwid: nil)
      if [username, password, license_key].any? { |v| v.nil? || v.strip.empty? }
        return { success: false, message: 'Username, password, and license_key are required' }
      end

      request(
        type: 'register',
        username: username,
        password: password,
        licenseKey: license_key,
        hwid: hwid || self.class.get_hwid
      )
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # SESSION MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════════

    # Validates the current session (heartbeat).
    #
    # @return [Boolean] True if session is valid.
    def check
      return false unless authenticated?

      result = request(type: 'check', sessionToken: @session_token)
      result[:success] == true
    end

    # Ends the current session and clears local state.
    #
    # @return [Boolean] True if logout was successful.
    def logout
      return false unless authenticated?

      result = request(type: 'logout', sessionToken: @session_token)
      if result[:success]
        @session_token = nil
        @username = nil
        @level = 0
        @subscription = nil
        @expires_at = nil
      end
      result[:success] == true
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # VARIABLES
    # ═══════════════════════════════════════════════════════════════════════════

    # Gets an application-level variable (shared across all users).
    #
    # @param key [String] Variable name.
    # @return [String, nil] Variable value or nil.
    def get_var(key)
      result = request(type: 'var', key: key, sessionToken: @session_token)
      result[:success] ? result.dig(:data, 'value') : nil
    end

    # Sets a user-level variable.
    #
    # @param key [String] Variable name.
    # @param value [String] Variable value.
    # @return [Boolean] True if saved.
    def set_var(key, value)
      result = request(type: 'setvar', key: key, value: value.to_s, sessionToken: @session_token)
      result[:success] == true
    end

    # Gets a user-level variable.
    #
    # @param key [String] Variable name.
    # @return [String, nil] Variable value or nil.
    def get_user_var(key)
      result = request(type: 'getvar', key: key, sessionToken: @session_token)
      result[:success] ? result.dig(:data, 'value') : nil
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # FILES
    # ═══════════════════════════════════════════════════════════════════════════

    # Lists all files available to the authenticated user.
    #
    # @return [Array<Hash>] Array of file hashes with id, name, size, minLevel.
    def list_files
      result = request(type: 'list_files', sessionToken: @session_token)
      result[:success] ? (result[:data] || []) : []
    end

    # Downloads a file by its ID and returns raw bytes.
    #
    # @param file_id [String] File ID from list_files.
    # @return [String, nil] Raw file content (binary string) or nil on failure.
    def download_file(file_id)
      return nil unless authenticated? && file_id && !file_id.empty?

      uri = URI.parse(@api_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 60

      payload = {
        type: 'file',
        appId: @app_id,
        apiKey: @api_key,
        fileId: file_id,
        sessionToken: @session_token
      }

      req = Net::HTTP::Post.new(uri.path)
      req['Content-Type'] = 'application/json'
      req['User-Agent'] = "Authon-Ruby-SDK/#{VERSION}"
      req.body = JSON.generate(payload)

      response = http.request(req)
      content_type = response['content-type'] || ''

      return response.body if content_type.include?('octet-stream')

      # Fallback: GET endpoint
      get_url = "#{@api_url}/files/download/#{URI.encode_www_form_component(file_id)}?token=#{URI.encode_www_form_component(@session_token)}"
      get_uri = URI.parse(get_url)
      get_resp = Net::HTTP.get_response(get_uri)
      get_ct = get_resp['content-type'] || ''
      return get_resp.body if get_ct.include?('octet-stream')

      nil
    rescue StandardError
      nil
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # LOGGING & ANALYTICS
    # ═══════════════════════════════════════════════════════════════════════════

    # Sends an activity log message to the dashboard.
    #
    # @param message [String] Log message (max 500 chars).
    # @return [Boolean] True if logged.
    def log(message)
      msg = message.to_s[0, 500]
      result = request(type: 'log', message: msg, sessionToken: @session_token)
      result[:success] == true
    end

    # Gets the list of currently online users.
    #
    # @return [Hash] {count: Integer, users: Array}
    def fetch_online
      result = request(type: 'fetch_online', sessionToken: @session_token)
      result[:success] ? (result[:data] || { 'count' => 0, 'users' => [] }) : { 'count' => 0, 'users' => [] }
    end

    # Gets application statistics.
    #
    # @return [Hash] {totalUsers, onlineUsers, totalKeys, appVersion}
    def fetch_stats
      result = request(type: 'fetch_stats', sessionToken: @session_token)
      result[:success] ? (result[:data] || {}) : {}
    end

    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY
    # ═══════════════════════════════════════════════════════════════════════════

    # Checks if an IP or HWID is blacklisted.
    #
    # @param ip [String, nil] IP address to check.
    # @param hwid [String, nil] HWID to check.
    # @return [Hash] {blacklisted: Boolean, reason: String|nil}
    def check_blacklist(ip: nil, hwid: nil)
      payload = { type: 'check_blacklist' }
      payload[:ip] = ip if ip && !ip.empty?
      payload[:hwid] = hwid if hwid && !hwid.empty?

      result = request(**payload)
      result[:success] ? (result[:data] || { 'blacklisted' => false, 'reason' => nil }) : { 'blacklisted' => false, 'reason' => nil }
    end

    # Redeems a referral code for bonus subscription days.
    #
    # @param code [String] Referral code.
    # @return [Hash] Response with success, message, data (expiresAt, rewardDays).
    def redeem_referral(code)
      request(type: 'redeem_referral', code: code, sessionToken: @session_token)
    end

    private

    # Sends a POST request to the Authon API.
    #
    # @param payload [Hash] Request payload.
    # @return [Hash] Parsed response {success:, message:, data:}
    def request(**payload)
      payload[:appId] = @app_id
      payload[:apiKey] = @api_key

      uri = URI.parse(@api_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.read_timeout = DEFAULT_TIMEOUT
      http.open_timeout = DEFAULT_TIMEOUT

      req = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
      req['Content-Type'] = 'application/json'
      req['User-Agent'] = "Authon-Ruby-SDK/#{VERSION}"
      req.body = JSON.generate(payload)

      response = http.request(req)
      parsed = JSON.parse(response.body)

      {
        success: parsed['success'] == true,
        message: parsed['message'],
        data: parsed['data']
      }
    rescue Net::OpenTimeout, Net::ReadTimeout
      { success: false, message: 'Request timed out. API may be overloaded.' }
    rescue Errno::ECONNREFUSED, SocketError
      { success: false, message: 'Connection failed. Check https://authon.pro/status' }
    rescue JSON::ParserError
      { success: false, message: 'Invalid response from server' }
    rescue StandardError => e
      { success: false, message: "Unexpected error: #{e.message}" }
    end

    # Extracts session data from response data hash.
    def extract_session(data)
      return unless data.is_a?(Hash)

      @session_token = data['sessionToken']
      @username = data['username']
      @level = data['level'].to_i
      @subscription = data['subscription']
      @expires_at = data['expiresAt']
    end
  end
end
