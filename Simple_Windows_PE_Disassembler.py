#!/usr/bin/env python3

# Simple Binary Disassembler

from capstone import * # http://www.capstone-engine.org/
import magic # https://pypi.org/project/python-magic/
import pefile # https://pypi.org/project/pefile/
import argparse # https://docs.python.org/3/library/argparse.html

PE32 = "PE32"

def main():
        parser = argparse.ArgumentParser(prog='dis')
        parser.add_argument('-i', dest='inputfile')
        args = parser.parse_args()
        if args.inputfile:
                if PE32 in magic.from_file(args.inputfile):
                        pe = pefile.PE(args.inputfile)
                        entryp = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                        data = pe.get_memory_mapped_image()[entryp:]
                else:
                        raise Exception("This file format is not supported")

                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                for i in cs.disasm(data, 0x1000):
                        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        else:
                parser.print_usage()

if __name__ == "__main__":
        main()

