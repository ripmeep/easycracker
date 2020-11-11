#!/usr/bin/env python3

import easycracker
import sys, time

hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99", # MD5 "password"
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", # SHA1 "hello"
	"a2217124a034c5c9ab3ad9746e00e40ecbbf1d85e60b9d7b9f549ce3", # SHA224 "goodpassword"
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9", # SHA256 "admin123" 
    "548568964fb078e3a030da81829aa18e88f93339bd1f480fc8fa795bb6bb95b87e9661eebea26e72163063d0bda11640", # SHA384 "dragon"
    "38221f3553236a28300b859c399a6e0cdc691b7c625bf23162c79c241a65635a348ffeb27f47a20cba5ee7a7c67ac2dfb686100dcd3abd7e4663cfacd9b25f80", # SHA512 "supersecret"
]

wordlist = "top-passwords.lst"


for hash in hashes:
	d = easycracker.DictionaryAttack(hash, wordlist)

	print("\nAttacking hash ({})".format(hash))

	d.start() # an FileNotFound error will occur if the wordlist cant be read or doesn't exist

	if d.cracked == True:
		print("Found the hash!")
		print("Hash Type: {}".format(d.hash_type))
		print("Plaintext: {}\n".format(d.plaintext.decode()))
	else:
		print("Could not find hash\n")
