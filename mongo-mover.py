import pymongo, subprocess, argparse, sys, os, datetime, shutil, zipfile
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2


def decrypt(args):
	print "Decrypting: "+str(args.inputfile)
	# input file
	try:
	    inputfile = open(args.inputfile, "rb")
	except IOError:
	    sys.exit("Could not open the input file "+str(args.inputfile))

	# output file
	try:
	    output = open(args.inputfiledestination+".decrypted", "wb")
	except IOError:
	    sys.exit("Could not create the output file "+str(args.inputfiledestination+".decrypted"))

	# make 256bits keys for encryption and mac
	salt = args.salt
	kdf = PBKDF2(args.key, salt, 64, 1000)
	key = kdf[:32]
	key_mac = kdf[32:]

	# create HMAC
	mac = HMAC.new(key_mac) # default is MD5

	data = inputfile.read()
	# check for MAC first
	verify = data[0:32]
	mac.update(data[32:])

	if mac.hexdigest() != verify:
	    sys.exit("Message was modified, aborting decryption.")

	# decrypt
	iv = data[32:48]
	cipher = AES.new(key, AES.MODE_CFB, iv)    

	decrypted = cipher.decrypt(data[48:])

	#output
	output.write(decrypted)
	#delete data from memory
	del salt
	del args	
	print 'Done!'

def dump_database(args):

	if os.path.isfile(args.destination):
		os.remove(args.destination)

	if os.path.isdir("dump"):
		shutil.rmtree("dump")

	command="mongodump -h "+args.server+" -d "+args.database
	process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
	output, error = process.communicate()

	zipf = zipfile.ZipFile(args.destination, 'w', zipfile.ZIP_DEFLATED)

	for root, dirs, files in os.walk("dump"):
		for file in files:
		    zipf.write(encrypt_file(os.path.join(root, file),args))
		    os.remove(os.path.join(root, file))
		    print 'Done!'

	zipf.close()

	if os.path.isdir("dump"):
		shutil.rmtree("dump")	


def encrypt_file(file, args):
	print 'Encrypting and writiing to zip file: '+str(file)+"..."
	# input file
	try:
	    inputfile = open(file, "rb")
	except IOError:
	    sys.exit("Could not open the exported destination file "+file)

	# output file
	try:
	    output = open(file+".encrypted", "wb")
	except IOError:
	    sys.exit("Could not create the encrypted output file "+file+".encrypted")

	# make 256bits keys for encryption and mac
	salt = args.salt
	kdf = PBKDF2(args.key, salt, 64, 1000)
	key = kdf[:32]
	key_mac = kdf[32:]

	# create HMAC
	mac = HMAC.new(key_mac) # default is MD5

	# encryption
	iv = os.urandom(16)
	cipher = AES.new(key, AES.MODE_CFB, iv)    

	encrypted = cipher.encrypt(inputfile.read())
	mac.update(iv + encrypted)

	# output
	output.write(mac.hexdigest())
	output.write(iv)
	output.write(encrypted)

	#delete data from memory
	del salt
	del args
	return file+".encrypted"	

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='MongoDB backup script with salted AES encryption/decryption.')
	parser.add_argument('-s','--server', action='store', dest="server", help="Server IP/DNS of MongoDB Server.")
	parser.add_argument('-db','--database', action='store', dest="database", help="Database within MongoDB to be backed up.")
	parser.add_argument('-ed','--export-destination', action='store', dest="destination", help="Path of the destination for the exported data.")
	parser.add_argument('-key','--key', action='store', dest="key", help="Key used to encrypt/decrypt data export.", reqired=True)
	parser.add_argument('-salt','--salt', action='store', dest="salt", help="Salt used to encrypt/decrypt data export.", reqired=True)	
	parser.add_argument("-d", "--decrypt", action="store_true")
	parser.add_argument("-i", "--inputfile", dest="inputfile", help="Inpute file to be decrypted.")
	parser.add_argument("-id", "--inputfile-destination", dest="inputfiledestination", help="Destination of decrypted input file.")	
	args = parser.parse_args()

	if args.decrypt:
		decrypt(args)
		sys.exit()

	dump_database(args)