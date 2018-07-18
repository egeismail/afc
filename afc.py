import os
import sys
import hashlib
import pyaes
import argparse
import struct
parser = argparse.ArgumentParser()
parser.add_argument("--filename","-F",help="File path to process")
parser.add_argument("--path","-P",help="Path to process")
parser.add_argument("--hexkey","-X",help="Hexdigest of Key. Length must be 32 digit")
parser.add_argument("--hexfile","-XF",help="Key file.(This file contents IV)")
parser.add_argument("--output","-o",help="Output filename of key.(If program executed without hexkey,This argument will be execute. If this argument won't be enter, program will create randomly get file name)")
parser.add_argument("--encrypt",help="Encrypt action",action="store_true")
parser.add_argument("--decrypt",help="Decrypt action",action="store_true")
arp = parser.parse_args()
def SHA256d(data):
    sh = hashlib.sha256()
    sh.update(data.encode("utf-8"))
    return sh.digest()
def SHA256hd(data):
    sh = hashlib.sha256()
    sh.update(data.encode("utf-8"))
    return sh.hexdigest()
def SHA512fd(fnamepath):
    sh5 = hashlib.sha512()
    with open(fnamepath,"rb") as fp:
        while True:
            tmp = fp.read(32768)
            if(not tmp):
                break
            sh5.update(tmp)
        fp.close()
    return sh5.digest()
def SHA512fhd(fnamepath):
    sh5 = hashlib.sha512()
    with open(fnamepath,"rb") as fp:
        while True:
            tmp = fp.read(32768)
            if(not tmp):
                break
            sh5.update(tmp)
        fp.close()
    return sh5.hexdigest()
def hextobytearray(data):
    buf = ""
    for i in range(len(data)/2):
        bt = data[i*2:(i+1)*2]
        if(not bt):
            break
        buf += chr(int("0x%s"%bt,0))
    return buf
def bytearraytohex(data):
    buf = ""
    for i in data:
        if(len(hex(ord(i))[2:]) == 1):
            buf += "0%s"%(hex(ord(i))[2:])
        else:
            buf+=hex(ord(i))[2:]
    return buf
class AESFileEncryptor(object):
    def __init__(self,key):
        global arp
        self.urandom = False
        self.Key = key
        if(not key):
            if(arp.hexfile):
                try:
                    self.LoadKey(arp.hexfile)
                except KeyboardInterrupt:
                    self.Key = os.urandom(32)
                    self.iv = "\x00"*16
                    self.urandom = True
            else:
                self.Key = os.urandom(32)
                self.iv = "\x00"*16
                self.urandom = True
        self.BUFFER = 32768
    def EncryptFile(self,Path):
        global arp
        ec = pyaes.AESModeOfOperationOFB(self.Key,iv=self.iv)
        processed_size = 0
        dgs = SHA512fd(Path)
        with open(Path,"rb") as fp:
            with open("%s.eca"%(Path),"wb") as fpb:
                fpb.write(dgs)
                osz = os.path.getsize(Path)
                while True:
                    tmp = fp.read(self.BUFFER)
                    if(not tmp):
                        break
                    processed_size+=len(tmp)
                    print "Encrypting%s\t%s [%s%s] %s%.3f\t\r"%("."*(3-(processed_size%3)),os.path.basename(Path),"#"*int(20*processed_size/osz)," "*(20-int(20*processed_size/osz)),"%",100.0*processed_size/osz),
                    e_data = ec.encrypt(tmp)
                    fpb.write(e_data)
                print "Encrypted %s to %s%s\r\n"%(Path,"%s%s"%(Path,".eca")," "*100),
        if(self.urandom):
            if(arp.output):
                filename = self.SaveKey(arp.output)
            else:
                filename = self.SaveKey("key")
            print "Key saved as %s"%(filename)
    def DecryptFile(self,Path):
        dc = pyaes.AESModeOfOperationOFB(self.Key,iv=self.iv)
        processed_size = 0
        osz = os.path.getsize(Path)-64
        sh5 = hashlib.sha512()
        with open(Path,"rb") as fp:
            sha512digest = fp.read(64)
            with open("%s"%Path[:1+(-len(".eca"))],"wb") as fpb:
                while True:
                    tmp = fp.read(self.BUFFER)
                    if(not tmp):
                        break
                    processed_size+=len(tmp)
                    print "Decrypting%s\t%s [%s%s] %s%.3f\t\r"%("."*(3-(processed_size%3)),os.path.basename(Path),"#"*int(20*processed_size/osz)," "*(20-int(20*processed_size/osz)),"%",100.0*processed_size/osz),
                    d_data = dc.decrypt(tmp)
                    sh5.update(d_data)
                    fpb.write(d_data)
                fpb.close()
            print "Checking... %s%s\r\n"%("%s"%Path[:1+(-len(".eca"))]," "*100),
            if(sh5.digest() != sha512digest):
                os.remove("%s"%Path[:1+(-len(".eca"))])
                print "Failed Decrypting on %s probably key error%s\r\n"%("%s"%Path[:1+(-len(".eca"))]," "*100),
            else:
                print "Decrypted %s to %s%s\r\n"%(Path,"%s"%Path[:1+(-len(".eca"))]," "*100),
    def SaveKey(self,fname):
        with open("%s.ecakey"%fname,"wb") as fp:
            fp.write(bytearraytohex("%s%s"%(self.Key,self.iv)))
            fp.close()
        return "%s.ecakey"%fname
    def LoadKey(self,fname):
        with open(fname,"rb") as fp:
            data = hextobytearray(fp.read())
            self.Key = data[:32]
            self.iv = data[32:32+16]
        print "Key loaded successfully."
def main():
    global arp,parser
    if(arp.hexkey):
        if(len(arp.hexkey) != 32):
            parser.print_usage()
            sys.exit()
    if((arp.filename or arp.path) and (arp.encrypt or arp.decrypt)):
        af = AESFileEncryptor(key = arp.hexkey)
        if(arp.path):
            pass
        elif(arp.filename):
            if(arp.encrypt):
                af.EncryptFile(arp.filename)
            elif(arp.decrypt):
                af.DecryptFile(arp.filename)
if __name__ == '__main__':
    main()
