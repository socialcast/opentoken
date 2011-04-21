# opentoken

Parse encrypted opentoken properties

see http://www.pingidentity.com/opentoken

## Usage

```ruby
# configure decryption with shared key
OpenToken.password = 'shared_secret_to_decrypt'

# decrypt opentoken into hash of attributes
attributes = OpenToken.parse 'opentoken-hashed-string'
```
  
## Contributing
 
* Fork the project
* Fix the issue
* Add tests
* Send me a pull request. Bonus points for topic branches.

see CONTRIBUTORS.txt for complete list of contributors.

## Copyright

Copyright (c) 2010 Socialcast Inc.
See LICENSE.txt for details.
