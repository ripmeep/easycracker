#!/usr/bin/env python3

# This type of attack, you only need a partial hash
# to find a potential match for plaintext
# and its really fast.

import easycracker

hashes = [
    	"5f4dcc3b5aa765d61", # MD5 "password"
	"aaf4c61ddcc5e8a2d", # SHA1 "hello"
	"a2217124a034c5c9a", # SHA224 "goodpassword"
    	"240be518fabd2724d", # SHA256 "admin123" 
    	"548568964fb078e3a", # SHA384 "dragon"
   	"38221f3553236a283", # SHA512 "supersecret"
]

hd = easycracker.HashDatabase()
hd.load("hashes.db")

for hash in hashes:
	print("\nSearching for partial hash ({})".format(hash))

	hd.search(hash)

	if hd.results == 0:
		print("Couldnt find any matches")
		continue

	for i in range(hd.results):
		entry = hd.get_result(i)

		plaintext = entry["plaintext"]
		algorithm = entry["algorithm"]

		print("Potential match => {}:{}\n".format(plaintext, algorithm))
