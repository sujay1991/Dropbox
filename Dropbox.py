# Include the Dropbox SDK
import dropbox

import os
import sys
import time

import random, struct
from Crypto.Cipher import AES

#Include WatchDog for monitoring the folder
from watchdog.observers import Observer  
from watchdog.events import PatternMatchingEventHandler

#Encryption
def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
            
#Decryption            
def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

#Authorization
class MyHandler(PatternMatchingEventHandler):
    patterns = ["*.*"]
    
    def process(self, event):
        path= event.src_path
        
        # Get your app key and secret from the Dropbox developer website
        app_key = '*****'
        app_secret = '*******'
        
        flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
        
        # Have the user sign in and authorize this token
        authorize_url = flow.start()
        print '1. Go to: ' + authorize_url
        print '2. Click "Allow" (you might have to log in first)'
        print '3. Copy the authorization code.'
        code = raw_input("Enter the authorization code here: ").strip()
        
        # This will fail if the user enters an invalid authorization code
        access_token, user_id = flow.finish(code)
        
        client = dropbox.client.DropboxClient(access_token)
        print 'linked account: ', client.account_info()
        print "______________________________________________"
        print "Encryption:\n"        
        infile=os.path.basename(path)
        
        encryptfile='en_'+infile
        
        key = raw_input("Enter 16 or 32 digit key for Encryption:\n")
        encrypt_file(key,infile,encryptfile)
        print "File Encrypted"
        encryptpath='C:\\Users\\Pavi\\Desktop\\'+encryptfile
        f = open(encryptpath, 'rb')
        response = client.put_file(encryptfile, f)
        print 'uploaded: ', response
        print "_______________________________________________"
        
        folder_metadata = client.metadata('/')
        print 'metadata: ', folder_metadata
        print "_______________________________________________"
        
        f, metadata = client.get_file_and_metadata(encryptfile)
        print "Decryption:\n"
        key1 = raw_input("Enter same 16 or 32 digit key for Decryption:\n")
        decryptfile='de_'+infile
        decrypt_file(key1,encryptfile,decryptfile)
        print metadata
        print "File Decrypted\n"

    def on_created(self, event):
        self.process(event) 

#Main Function Starts
if __name__ == "__main__":
    #event_handler = MyHandler()
    #print 'drop or modify files in the folder\n'
    monitorDirectory='C:\Users\Pavi\Desktop\Sync'
    print 'Add/Modify/Delete a file in the path given below:\n%s' % (monitorDirectory)
    observer = Observer()
    observer.schedule(MyHandler(),
                      path=monitorDirectory,
                      recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
