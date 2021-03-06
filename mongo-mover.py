import pymongo, subprocess, argparse, sys, os, datetime, shutil, zipfile, traceback, time, gzip
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2


def decrypt(args):
	if os.path.isdir("dump"):
		shutil.rmtree("dump")

	zip_ref = zipfile.ZipFile(args.destination, 'r')
	zip_ref.extractall()
	zip_ref.close()

	for root, dirs, files in os.walk("dump"):
		for file in files:
		    decrypt_file(os.path.join(root, file), args)
		    os.remove(os.path.join(root, file))


def decrypt_file(file, args):


	print("Decrypting: "+file)

	# input file
	try:
	    inputfile = open(file, "rb")
	except IOError:
	    sys.exit("Could not open the input file "+file)

	# output file
	try:
	    output = open(file[:-10], "wb")
	except IOError:
	    sys.exit("Could not create the output file "+file+".decrypted")

	# make 256bits keys for encryption and mac
	salt = args.salt.encode()
	kdf = PBKDF2(args.key, salt, 64, 1000)
	key = kdf[:32]
	key_mac = kdf[32:]

	# create HMAC
	mac = HMAC.new(key_mac) # default is MD5

	data = inputfile.read()
	# check for MAC first
	verify = data[0:32]
	mac.update(data[32:])

	if mac.hexdigest().encode() != verify:
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
	print('Done!')

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
		    print('Done!')

	zipf.close()

	if os.path.isdir("dump"):
		shutil.rmtree("dump")	


def encrypt_file(file, args):
	print('Encrypting and writiing to zip file: '+str(file)+"...")
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
	salt = args.salt.encode()
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
	output.write(mac.hexdigest().encode())
	output.write(iv)
	output.write(encrypted)

	#delete data from memory
	del salt
	del args
	return file+".encrypted"	


def scheduler(args):

	while True:
		orginaldestinaiton=args.destination
		path, file = os.path.split(args.destination)
		curtime = datetime.datetime.now()
		args.destination=path+"/"+str(curtime)+"-"+file
		try:
			dump_database(args)
			#sys.stdout.flush()
			print("On a schedule, sleeping for "+str(args.schedule)+" seconds...")
			args.destination=orginaldestinaiton
			time.sleep(float(args.schedule))


		except KeyboardInterrupt:
			print('Exiting gracefully...')

			if os.path.isdir("dump"):
				shutil.rmtree("dump")

			if os.path.isfile(args.destination):
				os.remove(args.destination)

			sys.exit()

		except:
			print('Backup failed at ' + str(datetime.datetime.now()))
			print(traceback.format_exc())

						


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='MongoDB backup script with salted AES encryption/decryption.')
	parser.add_argument('-s','--server', action='store', dest="server", help="Server IP/DNS of MongoDB Server.")
	parser.add_argument('-db','--database', action='store', dest="database", help="Database within MongoDB to be backed up.")
	parser.add_argument('-ez','--export-zip', action='store', dest="destination", help="Path of the destination for the exported data zip file.")
	parser.add_argument('-key','--key', action='store', dest="key", help="Key used to encrypt/decrypt data export.", required=True)
	parser.add_argument('-salt','--salt', action='store', dest="salt", help="Salt used to encrypt/decrypt data export.", required=True)
	parser.add_argument('-schedule','--schedule', action='store', dest="schedule", help="Seconds interval between backups.")	
	parser.add_argument("-d", "--decrypt", action="store_true")
	args = parser.parse_args()

	if args.decrypt:
		decrypt(args)
		sys.exit()

	if args.schedule:
		scheduler(args)
		sys.exit()

	dump_database(args)