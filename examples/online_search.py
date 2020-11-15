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

    print("\nSearching hash ({})".format(hash))

    l.search()

    if l.cracked == True:
        print("Found the hash!")
        print("Hash Type: {}".format(l.hash_type))
        print("Plaintext: {}\n".format(l.plaintext))
    else:
        print("Could not find hash\n".format(hash))
        
