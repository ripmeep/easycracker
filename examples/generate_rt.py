#!/usr/bin/env python3

import easycracker
import sqlite3
import random, sys
from tqdm import tqdm

f = open("top-passwords.lst", "r")
lines = f.readlines()

rt = easycracker.RainbowDatabase()

try:
	rt.create("hashes.db")
except Exception as e:
	print(str(e))
	sys.exit()

db = sqlite3.connect("hashes.db")
cur = db.cursor()

for i in tqdm(range(len(lines))):
	plaintext = lines[i].strip()

	try:
		plaintext = plaintext.decode("ascii")
	except:
		continue
		
	plaintext = plaintext.replace("'", "''") # It is SQL standard to replace all single quotes with double single quotes
	
	sys.stdout.write("\r[%s] Generaring Hash Tables "%(random.choice(["|", "/", "-", "\\"])))

	md4hash = easycracker.MD4Hash(plaintext).digest_dict()["hex"]
	md5hash = easycracker.MD5Hash(plaintext).digest_dict()["hex"]
	sha1hash = easycracker.SHA1Hash(plaintext).digest_dict()["hex"]
	sha224hash = easycracker.SHA224Hash(plaintext).digest_dict()["hex"]
	sha256hash = easycracker.SHA256Hash(plaintext).digest_dict()["hex"]
	sha384hash = easycracker.SHA384Hash(plaintext).digest_dict()["hex"]
	sha512hash = easycracker.SHA512Hash(plaintext).digest_dict()["hex"]

	cur.execute(rt.craft_entry(plaintext, md4hash, "MD4"))
	cur.execute(rt.craft_entry(plaintext, md5hash, "MD5"))
	cur.execute(rt.craft_entry(plaintext, sha1hash, "SHA1"))
	cur.execute(rt.craft_entry(plaintext, sha224hash, "SHA224"))
	cur.execute(rt.craft_entry(plaintext, sha256hash, "SHA256"))
	cur.execute(rt.craft_entry(plaintext, sha384hash, "SHA384"))
	cur.execute(rt.craft_entry(plaintext, sha512hash, "SHA512"))

db.commit()

