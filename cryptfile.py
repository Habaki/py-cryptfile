#!/usr/bin/env python

'''
	cryptfile.py:
	Encode/Decode utilities based on AES (mode feature to come).
	Current version 1.3.0
	
	Written by Lorenzo La Spina 2014.
	Original encode/decode Federico Fucci

	(c) Copyright 2014 Lorenzo La Spina and Federico Fucci.

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser GPL v3
	as published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
	http://www.gnu.org/licenses/lgpl-3.0.txt for more details.

	You should have received a copy of the GNU Lesser GPL v3
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import sys, getopt
import base64
import os

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#This helper function returns the file content in a string
def read_file(filename):
	print '[INFO] Reading file'
	try:
		with open(filename, 'r') as file_content:
			content = file_content.read()
			file_content.close()
	except TypeError:
		#we are trying to decode a file that is not crypted, exception
		print '[ERROR] Invalid Input File. Check file.'
		sys.exit()	
	return content

#This helper function writes the decrypted buffer to a file
def write_file(filename, buffer_to_write):
	print '[INFO] Writing file'
	root, ext = os.path.splitext(filename)
	
	if (ext == '.crypto'):
		#we are decrypting, remove extension
		filename = root
	else:
		#add extension for crypted file
		filename = filename + '.crypto'

	with open(filename, 'w') as result_file:
		#try convert buffer to utf-8 before saving, if not valid invalid password
		try:
			result_file.write(unicode(buffer_to_write, "UTF-8"))
			result_file.close()
		except UnicodeDecodeError:
			print '[ERROR] Invalid Password.'
			os.remove(filename)
			sys.exit()

def crypt_magic(filename, pwd, what_to_do):
	'''
	print '[Debug] filename: ' + filename
	print '[Debug] pwd: ' + pwd
	print '[Debug] what to do: ' + what_to_do
	'''
	#crypt magic
	h = SHA256.new()
	h.update(pwd)
	pwd = h.digest()
	cipher = AES.new(pwd)
	#get file content
	file_buffer = read_file(filename)
	if(what_to_do == 'encode'):
		encoded = EncodeAES(cipher, file_buffer)
		write_file(filename, encoded)
	elif(what_to_do == 'decode'):
		decoded = DecodeAES(cipher, file_buffer)
		write_file(filename, decoded)
	
def main(argv):
	inputfile = ''
	password = ''
	#print '[Debug] Executing main function'
	try:
		opts, args = getopt.getopt(argv, "hp:c:d:", ["pass=", "cryptfile=", "decryptfile="])
	except getopt.GetoptError:
		print "Invalid Arguments."
		sys.exit(2)
	
	for opt, arg in opts:
		#print '[Debug] opt, arg: ' + opt + ' ' + arg
		if opt in ("-h", "--help"):
			print '===cryptfile.py v1.3.0 is a simple Encode/Decode utility written with python and love by Lorenzo La Spina 2014.===\n -c, --cryptfile <file to crypt>	to encode a file. \n -d, --decryptfile <file to decrypt>	to decode a file. \n -p, --password <password>		to input a password for the file. \n -h, --help				to view this help message.'
			sys.exit()
		elif opt in ("-p", "--password"):
			password = arg
		elif opt in ("-c", "--cryptfile"):
			crypt_magic(arg, password, 'encode')
			break
		elif opt in ("-d", "--decryptfile"):
			crypt_magic(arg, password, 'decode')
			break

if __name__ == "__main__":
	main(sys.argv[1:])
