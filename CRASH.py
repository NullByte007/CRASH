#!/usr/bin/python3
# Copyright 2020, Aniket.N.Bhagwate, All rights reserved.
# Date Created : 31st March 2020
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import os
import crypt
from time import sleep
import time
import sys
import hashlib

banner="""
\t+==========================================+
\t+===   ____ ____      _    ____  _   _  ===+
\t+===  / ___|  _ \    / \  / ___|| | | | ===+
\t+=== | |   | |_) |  / _ \ \___ \| |_| | ===+
\t+=== | |___|  _ <  / ___ \ ___) |  _  | ===+
\t+===  \____|_| \_\/_/   \_\____/|_| |_| ===+
\t+==========================================+ 
\t+======== CRACK HASHES WITH EASE ==========+
\t+==========================================+
\t+==CODED BY NULLBYTE007 (Aniket Bhagwate)==+
\t+==========================================+                                 
\n
"""

algorithm_banner = """

\t+==============+
\t+ [1] MD5      +
\t+==============+
\t+ [2] SHA1     +
\t+==============+
\t+ [3] SHA512   +
\t+==============+
\t+ [4] SHA256   +
\t+==============+
\t+ [5] SHA384   +
\t+==============+
\t+ [6] SHA224   +
\t+==============+
"""

def bannerD():
	os.system("clear")
	print(banner)

def shadowAccess():
	bannerD()
	choice = input("[?] WHICH SHADOW FILE DO YOU WISH TO ACCESS : ( Remote(R) / Local(L) ) : " ).lower()
	f=''
	users=[]
	cnt=1
	if choice=='l':
		try:
			f = open("/etc/shadow",'r')
			f = f.read().split("\n")
			f.pop()
		
		except:
			print("[!] UNABLE TO ACCESS SHADOW FILE ! [TRY RUNNING WITH SUDO]")	
		
	elif choice=='r':
		choice = input("[?] ENTER FILE PATH FOR SHADOW FILE : ")
		try:
			f = open("{}".format(choice),'r')
			f = f.read().split("\n")
			f.pop()
		except:
			print("[!] UNABLE TO LOCATE/OPEN FILE !! ")
			main()
	
	
	print("\n[*] READING FILE AND GETTING USERS ")
	sleep(1)
	for x in f:
		if x.split(":")[1]=='*' or x.split(":")[1]=='!' or x.split(":")[1]=='!!':
			pass
		else:
			users.append(x)

	for x in users:
		print("+--------------------------------------+")
		print("   [ {} ] ".format(cnt) + "\033[30;42;5m {} \033[m ".format(x.split(':')[0]) )
		cnt+=1
	print("+--------------------------------------+\n")
	
	choice = int(input("[?] SELECT USER :  "))
	
	input("< PRESS ENTER >")
	
	getInfo( users[choice-1] , users[choice-1].split(":")[0] )

	

def getInfo(user,x):
	bannerD()
	algorithms = {'1':"MD5" ,'2a':"BLOWFISH",'2y':"BLOWFISH",'5':"SHA-256",'6':"SHA-521"}

	print("[*] INFORMATION ABOUT : \033[30;42;5m {} \033[m ".format(x))
	user = user.split(":")[1]
	user = user.split("$")
	algo = user[1]
	salt = user[2]
	pass_hash = user[3]

	print("\n+====================================================================================================================+")
	print("[*] ALGORITHM USED IS   : \033[30;42m {} \033[m ".format(algorithms[algo]))
	print("\n[*] SALT USED IS        : \033[30;42m {} \033[m ".format(salt))
	print("\n[*] PASSWORD HASH IS    : \033[30;42m {} \033[m ".format(pass_hash))
	print("+====================================================================================================================+")

	input("< PRESS ENTER >")
	hashCrack(algo,salt,pass_hash)


def hashCrack(algo,salt,pass_hash):
	bannerD()
	hash_count=1
	v1=v2=1
	space="  "
	salt_algo="${}${}".format(algo,salt)
	try:
		wordlist = input("[*] ENTER WORDLIST NAME / PATH : ")
		f = open("{}".format(wordlist),'r',encoding="ISO-8859-1")
		f = f.read().split("\n")
		f.pop()
		

	except:
		print("[!] UNABLE TO LOCATE/OPEN FILE !! ")
		hashCrack()

	start_time = time.time()
	input("\n[!] PRESS ENTER TO START CRACKING ! \n")
	for x in f:
		hash_value = crypt.crypt("{}".format(x) ,"{}".format(salt_algo))
		hash_value = hash_value.split("$")[3]
		
		if pass_hash==hash_value:
			bannerD()
			print("\t\033[30;42;5m !! HASH MATCHED !! \033[m ")
			
			os.system("{} sed -n '{},{}p' {}  > found.txt".format(space,v1,v2,wordlist))
			
			f = open("found.txt",'r')
			f = f.read().split("\n")[0]
			print("\n+===============================================+")
			print("\tPASSWORD IS : ==>  \033[30;42m {} \033[m".format(f))
			print("+===============================================+")
			
			tim = str(time.time()-start_time)
			tim = tim.split(".")
			tim = int(tim[0])
			print("\n\tCOMPLETED CRACKING IN {} SECONDS ! ".format(tim))
			print("\n\tWORDS CHECKED PER SECOND ==> {}\n".format( str(hash_count/tim).split(".")[0] ) )
			sys.exit(0)
 

		os.system("clear")
		bannerD()
		print("\n\n+=====================================================+")
		print("|     CHECKING HASH FOR  ==> {}".format(x))
		print("+=====================================================+")
		print("|     HASH VALUES TESTED : {} ".format(hash_count) )
		print("+=====================================================+")
		print("|     TIME ELAPSED: {} ------".format(time.time() - start_time))
		print("+=====================================================+")
		
		hash_count+=1
		v1+=1
		v2+=1
		time.sleep(0.001)


	print("NO MATCH FOUND ! ")



def data_crack():
	bannerD()
	hash_count=1
	v1=v2=1
	algo = {'1':'md5' , '2':'sha1' , '3':'sha512' , '4':'sha256', '5':'sha384', '6':'sha224' }
	hash_value = input("[?] ENTER THE DATA HASH : ")
	print(algorithm_banner)
	choice = input("\n[?] SELECT THE HASH ALGORITHM : ")

	try:
		wordlist = input("[*] ENTER WORDLIST NAME / PATH : ")
		f = open("{}".format(wordlist),'r',encoding="ISO-8859-1")
		f = f.read().split("\n")
		f.pop()
		

	except:
		print("[!] UNABLE TO LOCATE/OPEN FILE !! ")
		data_crack()
		
	
	def crack_dhash(x,hash_count,v1,v2):
		if x==hash_value:
			bannerD()
			print("\t\033[30;42;5m !! HASH MATCHED !! \033[m ")
			
			os.system("sed -n '{},{}p' {}  > found.txt".format(v1,v2,wordlist))
			
			f = open("found.txt",'r')
			f = f.read().split("\n")[0]
			print("\n+===============================================+")
			print("\tDATA IS : ==>  \033[30;42m {} \033[m".format(f))
			print("+===============================================+")
			
			tim = str(time.time()-start_time)
			tim = tim.split(".")
			tim = int(tim[0])
			print("\n\tCOMPLETED CRACKING IN {} SECONDS ! ".format(tim))
			print("\n\tWORDS CHECKED PER SECOND ==> {}\n".format( str(hash_count/tim).split(".")[0] ) )
			sys.exit(0)
 

		os.system("clear")
		bannerD()
		print("\n\n+=====================================================+")
		print("|     HASH VALUES TESTED : {} ".format(hash_count) )
		print("+=====================================================+")
		print("|     TIME ELAPSED: {} ------".format(time.time() - start_time))
		print("+=====================================================+")
		
		time.sleep(0.001)
		


	
			
	
	start_time = time.time()
	
	if choice=='1':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.md5(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
			
		
	elif choice=='2':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.sha1(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
			
	elif choice=='3':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.sha512(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)	
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
			
			
	elif choice=='4':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.sha256(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)	
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
			
			
	elif choice=='5':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.sha384(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)	
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
			
			
	elif choice=='6':
		input("[!] PRESS ENTER TO START SCANNING..")
		for x in f:
			gen_hash = hashlib.sha224(f"{x}".encode()).hexdigest()
			crack_dhash(gen_hash,hash_count,v1,v2)	
			hash_count+=1
			v1+=1
			v2+=1
		bannerD()
		input("NO MATCH FOUND ! ")
		main()
	
	

def main():
	bannerD()
	print("+=======================================+")
	print("+ [1] CRACK SHADOW FILE HASH            +")
	print("+=======================================+")
	print("+ [2] CRACK SEPERATE HASH               +")
	print("+=======================================+")
	
	choice = input("\n[*] CHOOSE YOUR OPTION :  ")
	try:
		if choice=='1':
			shadowAccess()
	
		elif choice=='2':
			data_crack()
	except:
		sys.exit(0)
if __name__=='__main__':
	main()

