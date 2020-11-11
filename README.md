# easycracker
A simple to use python3 module for hashes and attacking hashes

# install

    $ git clone https://github.com/ripmeep/easycracker
    $ cd easycracker/
    
    $ apt-get install libssl-dev
    $ apt-get install libcurl4-openssl-dev

    $ python3 setup.py build
    $ python3 setup.py install
    
    $ echo "Finished :)"
    
# hash usage

The hashing library supports MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512

```python
import easycracker

md5hash = easycracker.MD5Hash("hello").digest_dict()
# {'plaintext': 'hello', 'raw': b']A@*\xbcK*v\xb9q\x9d\x91\x10\x17\xc5\x92', 'hex': '5d41402abc4b2a76b9719d911017c592'}

sha512hash = easycracker.SHA512Hash("hello").digest_dict()["hex"] 
# 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043

# You can also just call digest() for the raw hash on its own.
# After digest() or digest_dict(), the hex encoded hash will be stored in .hex_value
# And the normal, raw digested hash will be stored in the objects .value attribute

print(sha512hash.plaintext)
# hello

print(sha512hash.value)
# b'\x9bq\xd2$\xbdb\xf3x]\x96\xd4j\xd3\xea=s1\x9b\xfb\xc2\x89\x0c\xaa\xda\xe2\xdf\xf7%\x19g<\xa7##\xc3\xd9\x9b\xa5\xc1\x1d|z\xccn\x14\xb8\xc5\xda\x0cFcG\\.\\:\xde\xf4os\xbc\xde\xc0C'

print(sha512hash.hex_value)
# 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
```

# dictionary attack example

This is an easy way to perform a dictionary attack with the module using a hash, and a wordlist
Supports: MD5, SHA1, SHA224, SHA256, SHA384, SHA512   (Linux Crypt hash coming soon)

```python
import easycracker

d = easycracker.DictionaryAttack("5d41402abc4b2a76b9719d911017c592", "rockyou.txt")
d.start()

if d.cracked:
  print("Found the hash after %d attempts!"%( d.attempt ))
  print("[%s] %s:%s"%( d.hash_type, d.hash_value, d.plaintext.decode() ))
  
  # "[MD5] 5d41402abc4b2a76b9719d911017c592:hello"
else:
  print("Could not find the hash")
```

# online API crack

This is a way to search for a hash's plaintext online using this module. Only a valid hash is required (MD5, SHA1, SHA256, SHA384, SHA512)

```python
#!/usr/bin/env python3

import easycracker

hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99", # MD5 "password"
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", # SHA1 "hello"
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9", # SHA256 "admin123"
    "548568964fb078e3a030da81829aa18e88f93339bd1f480fc8fa795bb6bb95b87e9661eebea26e72163063d0bda11640", # SHA384 "dragon"
    "38221f3553236a28300b859c399a6e0cdc691b7c625bf23162c79c241a65635a348ffeb27f47a20cba5ee7a7c67ac2dfb686100dcd3abd7e4663cfacd9b25f80", # SHA512 "supersecret"
]


for hash in hashes:
    l = easycracker.OnlineLookup(hash)

    l.search()

    print("\nSearching hash ({})".format(hash))

    if l.cracked == True:
        print("Found the hash!")
        print("Hash Type: {}".format(l.hash_type))
        print("Plaintext: {}\n".format(l.plaintext))
    else:
        print("Could not find hash\n".format(hash))
```
