#!/usr/bin/env python3

# Product ID Extractor for parsing msobj140-msvcrt.lib

import argparse
import re
import struct

def main():
         parser = argparse.ArgumentParser()
         parser.add_argument('-i', type=str, help='Inputfile', required=True, dest='inputfile')
         args = parser.parse_args()
         f = open(args.inputfile, 'rb')
         data = f.read()
         f.close()
         for match in re.finditer(rb'prodid[_0-9a-zA-Z]{2,}',data):
                 id = struct.unpack_from('H',data,match.start()-2)
                 product = match.group(0)[6:].decode('utf-8')
                 print(id[0],product)
if name == "main":
     main()