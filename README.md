# Authon Ruby SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Ruby SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/MTY79JDFm6">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Ruby 2.7+
- No external gems required (uses stdlib net/http)

## Installation

Copy `authon.rb` into your project:
```ruby
require_relative 'authon'
```

## Quick Start

```ruby
auth = Authon.new('your-app-id', 'your-api-key')
auth.init

result = auth.login('username', 'password')
if result['success']
  puts "Level: #{auth.level}"
end
auth.logout
```

## Run Example

```bash
ruby example.rb
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/MTY79JDFm6
- 📊 Status: https://authon.pro/status
- 🔗 API Health: https://api.authon.pro/health

## License

MIT
