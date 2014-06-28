#!/usr/bin/env python

##	@package cryptfile.py:
#	Encode/Decode utilities based on AES (mode feature to come).
#	Current version 1.5.3
#	
#	Written by Lorenzo La Spina 2014.
#	Original encode/decode Federico Fucci based on PyCrypto 2.6.1
#
#	(c) Copyright 2014 Lorenzo La Spina and Federico Fucci.
#
#	This program is free and open software; you can redistribute
#   it and/or modify it under the terms of the GNU Lesser GPL v3
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
#	http://www.gnu.org/licenses/lgpl-3.0.txt for more details.
#
#	You should have received a copy of the GNU Lesser GPL v3
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import sys, getopt
import base64
import os

## @var BLOCK_SIZE 
# The block size for the cipher object; must be 16, 24, or 32 for AES.
BLOCK_SIZE = 32

## @var PADDING
# The character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE.
PADDING = '{'

## One-liner to sufficiently pad the text to be encrypted.
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

## One-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64.
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

## Helper function that returns the file content in a string.
# @param filename: the file to read.
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

## Helper function that writes the encoded or decoded buffer to a file,
# it checks the extersion to understand what kind of file to output.
# It can be aour.crypto file or the file with the original extension to
# avoid data corruption.
# @param filename: the output file named after the input one.
# @param buffer_to_write: the encoded/decoded buffer.
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
		
## This is the core method that applies the encode/decode juice
# to the buffer extracted from the file.
# @param filename: the input file name.
# @param pwd: the password to open the input file.
# @param method: type of encode/decode function.
# @param *args: arguments of the encode/decode method.
def crypt_magic(filename, pwd, method):
	#crypt magic
	h = SHA256.new()
	h.update(pwd)
	pwd = h.digest()
	cipher = AES.new(pwd)
	#get file content
	file_buffer = read_file(filename)
	
	buffer_to_write = method(cipher, file_buffer)
	write_file(filename, buffer_to_write)
	
	#deprecated C-Style approach
	'''
	if(what_to_do == 'encode'):
		encoded = EncodeAES(cipher, file_buffer)
		write_file(filename, encoded)
	elif(what_to_do == 'decode'):
		decoded = DecodeAES(cipher, file_buffer)
		write_file(filename, decoded)
	'''

## Quick and dirty helper function to detect if the user gave a
# password as command line argument.
# (Resolve Bug #0001: Password MUST be the first argument)
# Password can be in any position of the command line.
# @param options: the list of the command line options.
def check_for_pwd(options):
	for opt, arg in options:
		if opt in ("-p", "--password"):
			password = arg
		else:
			password = ""
	return password

def main(argv):
	
	try:
		opts, args = getopt.getopt(argv, "hp:c:d:", ["pass=", "cryptfile=", "decryptfile="])
	except getopt.GetoptError:
		print "Invalid Arguments."
		sys.exit(2)
		
	password = check_for_pwd(opts)
	
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			print '===cryptfile.py v1.5.3 is a simple Encode/Decode utility written with python and love by Lorenzo La Spina 2014.===\n -c, --cryptfile <file to crypt>	to encode a file. \n -d, --decryptfile <file to decrypt>	to decode a file. \n -p, --password <password>		to input a password for the file. \n -h, --help				to view this help message.'
			sys.exit()
		elif opt in ("-c", "--cryptfile"):
			crypt_magic(arg, password, EncodeAES)
			break
		elif opt in ("-d", "--decryptfile"):
			crypt_magic(arg, password, DecodeAES)
			break

if __name__ == "__main__":
	main(sys.argv[1:])
