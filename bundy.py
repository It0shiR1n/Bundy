import argparse
import hashlib



# MENU
def menu():
    print(f'''               ...                            
              ;::::;        By: Sh4d0wgh0s7                
            ;::::; :;                       
          ;:::::'   :;                     
          ;:::::;     ;.                        
        ,:::::'       ;           OOO\         
        ::::::;       ;          OOOOO\        
        ;:::::;       ;         OOOOOOOO       
        ,;::::::;     ;'         / OOOOOOO      
      ;:::::::::`. ,,,;.        /  / DOOOOOO    
    .';:::::::::::::::::;,     /  /     DOOOO   
  ,::::::;::::::;;;;::::;,  (), bl::# /     DOO
  `:`:::::::`;:::::: ;::::::#/               DOO
  :::`:::::::`;; ;:::::::::##                OO
  ::::`:::::::`;::::::::;:::#                OO
  `:::::`::::::::::::;'`:;::#                O ''')
  


# Bruteforce Functions
# ================================================================================

def decMD5(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.md5(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")
            
            return f"[+] Password Found: {word}"

    return False



def decMD5salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.md5(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")
            
            return f"[+] Password Found: {word}"

    return False




def decSHA1(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha1(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA1salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha1(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA224(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha224(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA224salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha224(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA256(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA256salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA384(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha384(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False

def decSHA384salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha384(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA512(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha512(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA512salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha512(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA3_224(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha3_224(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False    


def decSHA3_224salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha3_224(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA3_256(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha3_256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA3_256salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha3_256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decSHA3_384(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha3_384(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA3_384salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha3_384(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False






def decSHA3_512(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.sha3_512(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decSHA3_512salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.sha3_512(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decBlake2b(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.blake2b(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decBlake2bsalt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.blake2b(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decBlake2s(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.blake2s(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decBlake2ssalt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.blake2s(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decShake_128(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.shake_128(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False



def decShake_128salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.shake_128(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False





def decShake_256(hash, wordlist):
    menu()
    for word in wordlist:
        hashed = hashlib.shake_256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False


def decShake_256salt(hash, salt, wordlist):
    menu()
    for word in wordlist:
        hashed = salt + hashlib.shake_256(str.encode(word)).hexdigest()
        print(f"[#] Hash: {hashed}", end="\r")

        if (hashed == hash):
            print("\r")
            print(f"[+] Password Found: {word}")

            return f"[+] Password Found: {word}"

    return False

# ================================================================================


# The Arguments 
# ================================================================================ 

parser = argparse.ArgumentParser()

parser.add_argument("-t", "--type", help="Set the hash type: sha1, sha512, md5", required=True)
parser.add_argument("--hash", help="set the file that contains the hash", required=True)
parser.add_argument("-w", "--wordlist", help="set the wordlist", required=True)
parser.add_argument("-s", "--salt", help="set the salt")
parser.add_argument("-o", "--output", help="creates a file with the output: pls set the nameof archive, ex: '-o nameofarchive.txt'")

arguments = parser.parse_args()


# ================================================================================


# The main program
# ================================================================================
algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256"]

typeHash = arguments.type.lower()
hash = open(arguments.hash).read() 
wordlist = open(arguments.wordlist).read().split("\n")


if (typeHash in algorithms):
    if arguments.salt:
        salt = arguments.salt

        if arguments.output:
            if (typeHash == "md5"):
                ret = decMD5salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

                

            elif (typeHash == "sha1"):
                ret = decSHA1salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha224"):
                ret = decSHA224salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha256"):
                ret = decSHA256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha384"):
                ret = decSHA384salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha512"):
                ret = decSHA512salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_224"):
                ret = decSHA3_224salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_256"):
                ret = decSHA3_256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_384"):
                ret = decSHA3_384salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_512"):
                ret = decSHA3_512salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "blake2b"):
                ret = decBlake2bsalt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "blake2s"):
                ret = decBlake2ssalt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "shake_128"):
                ret = decShake_128salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "Shake_256"):
                ret = decShake_256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()




        else:
            if (typeHash == "md5"):
                ret = decMD5salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                

            elif (typeHash == "sha1"):
                ret = decSHA1salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               


            elif (typeHash == "sha224"):
                ret = decSHA224salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                

            elif (typeHash == "sha256"):
                ret = decSHA256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               

            elif (typeHash == "sha384"):
                ret = decSHA384salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                

            elif (typeHash == "sha512"):
                ret = decSHA512salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               

            elif (typeHash == "sha3_224"):
                ret = decSHA3_224salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "sha3_256"):
                ret = decSHA3_256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               


            elif (typeHash == "sha3_384"):
                ret = decSHA3_384salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "sha3_512"):
                ret = decSHA3_512salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "blake2b"):
                ret = decBlake2bsalt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "blake2s"):
                ret = decBlake2ssalt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "shake_128"):
                ret = decShake_128salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "Shake_256"):
                ret = decShake_256salt(hash, salt, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()


    else:
        if arguments.output:
            if (typeHash == "md5"):
                ret = decMD5salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

                

            elif (typeHash == "sha1"):
                ret = decSHA1salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha224"):
                ret = decSHA224salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha256"):
                ret = decSHA256salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha384"):
                ret = decSHA384salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

            elif (typeHash == "sha512"):
                ret = decSHA512salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_224"):
                ret = decSHA3_224salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_256"):
                ret = decSHA3_256salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_384"):
                ret = decSHA3_384salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "sha3_512"):
                ret = decSHA3_512salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "blake2b"):
                ret = decBlake2bsalt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "blake2s"):
                ret = decBlake2ssalt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "shake_128"):
                ret = decShake_128salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()


            elif (typeHash == "Shake_256"):
                ret = decShake_256salt(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                else:
                    arq = open(arguments.output, "a")
                    arq.write(ret)
                    arq.close()

                
        else:
            if (typeHash == "md5"):
                ret = decMD5(hash,wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()
                
                
                

            elif (typeHash == "sha1"):
                ret = decSHA1(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "sha224"):
                ret = decSHA224(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                

            elif (typeHash == "sha256"):
                ret = decSHA256(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               

            elif (typeHash == "sha384"):
                ret = decSHA384(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                

            elif (typeHash == "sha512"):
                ret = decSHA512(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                


            elif (typeHash == "sha3_224"):
                ret = decSHA3_224(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

               


            elif (typeHash == "sha3_256"):
                ret = decSHA3_256(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                


            elif (typeHash == "sha3_384"):
                ret = decSHA3_384(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "sha3_512"):
                ret = decSHA3_512(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                


            elif (typeHash == "blake2b"):
                ret = decBlake2b(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "blake2s"):
                ret = decBlake2s(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()

                


            elif (typeHash == "shake_128"):
                ret = decShake_128(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()



            elif (typeHash == "Shake_256"):
                ret = decShake_256(hash, wordlist)

                if (ret == False):
                    print("could not find the password with this wordlist, try another one...") 
                    exit()
          

else:
    menu()   
    print("please specify an algorithm that you have in the list:")
    for word in algorithms:
        print(word)

# ================================================================================