#!/usr/bin/env python3

# Simple Rich Header Reader and Checksum Calculator

import magic # https://pypi.org/project/python-magic/
import pefile # https://pypi.org/project/pefile/
import argparse # https://docs.python.org/3/library/argparse.html

PE32 = "PE32"
DANS = 128

def rol(val, num):
         return ((val << (num & 0x1f)) & 0xffffffff) | (val >> (32 - (num & 0x1f)))

def processPE(file):
         pe = pefile.PE(file)
         data = open(file, 'rb')
         if (pe.RICH_HEADER):
                 checksum = DANS
                 checkbuf = data.read(DANS) # read in up to the start of the rich header
                 for i in range(0, len(checkbuf)):
                         if ((i<0x3b) | (i>0x3f)):
                                 checksum += rol(checkbuf[i],i)
                 print("[Rich Header Stamp]")
                 for re in range(0, len(pe.RICH_HEADER.values), 2):
                         id = pe.RICH_HEADER.values[re] >> 16
                         version = pe.RICH_HEADER.values[re] & 0xffff
                         count = pe.RICH_HEADER.values[re + 1]
                         checksum += rol(pe.RICH_HEADER.values[re],pe.RICH_HEADER.values[re+1])
                         print("ID:\t {} version:\t {} count:\t {}".format(id,version,count))
                 checksum &= 0xffffffff
                 if (checksum != pe.RICH_HEADER.checksum):
                         print("Checksums do NOT match: ",end="")
                 else:
                         print("Checksums match: ",end="")
                 print("original header: {} calculated: {}" .format(hex(pe.RICH_HEADER.checksum),hex(checksum)))
         else:
                 print("No Rich header")
def main():
         parser = argparse.ArgumentParser(prog='dis')
         parser.add_argument('-i', dest='inputfile')
         args = parser.parse_args()
         if args.inputfile:
                 if PE32 in magic.from_file(args.inputfile):
                         processPE(args.inputfile);
                 else:
                         raise Exception("This file format is not supported")
         else:
                 parser.print_usage()
if name == "main":
         main()