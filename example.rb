# Authon Ruby SDK - Full Usage Example
# Run: ruby example.rb

require_relative 'authon'

# ============ SETUP ============
auth = Authon.new('your-app-id', 'your-api-key')

# ============ CONNECT ============
unless auth.init
  puts '[-] Failed to connect to Authon API'
  exit 1
end
puts "[+] Connected: #{auth.app_name} v#{auth.app_version}"

# ============ AUTHENTICATE ============
puts "\n[1] Login (Username + Password)"
puts '[2] License Key'
print "\n> "
choice = gets.chomp

if choice == '1'
  print 'Username: '
  username = gets.chomp
  print 'Password: '
  password = gets.chomp
  result = auth.login(username, password)
else
  print 'License Key: '
  key = gets.chomp
  result = auth.license(key)
end

unless result['success']
  puts "\n[-] #{result['message']}"
  exit 1
end

puts "\n[+] Authenticated!"
puts "    Level: #{auth.level}"
puts "    Subscription: #{auth.subscription || 'None'}"
puts "    Expires: #{auth.expires_at || 'Lifetime'}"

# ============ USE FEATURES ============
msg = auth.get_var('welcome_message')
puts "\n[*] #{msg}" if msg

files = auth.list_files
if files.any?
  puts "\n[*] Available files (#{files.length}):"
  files.each_with_index do |f, i|
    puts "    [#{i + 1}] #{f['name']} (#{(f['size'] || 0) / 1024} KB)"
  end
end

auth.log('Ruby SDK example executed')

# ============ CLEANUP ============
puts "\n[+] Done. Logging out..."
auth.logout
