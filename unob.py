#!/usr/bin/env python3
# Header Repair for UPX Packed Executables
# WARNING: This is experimental proof-of-concept not production quality code

import magic  # https://pypi.org/project/python-magic/
import pefile  # https://pypi.org/project/pefile/
import argparse  # https://docs.python.org/3/library/argparse.html
import mmap
import binascii

PE32 = "PE32"
ELF = "ELF"
UPX = b"UPX!"


def processPE(file):
    print("Processing PE32 binary")


def printHex(buf):
    print(binascii.hexlify(buf))


def processELF(mm):
    # see if we find a duplicate ELF after the program headers
    elf = mm.find(b"ELF", 10)
    if elf:
        # first see if there is an obvious header
        obviousupx = mm.find(UPX, 10)
        if (obviousupx < elf):
            mm.seek(obviousupx)
            upxhdr = obviousupx
        else:
            # name may be changed, backtrack above it to see if we find a UPX header
            upxhdr = elf - 34
            print("Did not find an obvious UPX header; trying at:", upxhdr)
            mm.seek(upxhdr)
            upxheader = mm.read(30)
            magic = upxheader[0:4]
            version = upxheader[6]
            format = upxheader[7]
            if ((format > 1) & (format < 143)):
                if ((version > 1) & (version < 16)):
                    mm.seek(upxhdr)
            else:
                print("Could not locate the UPX header");
                return -1

        upxheader = mm.read(30)
        print("UPX Header:", binascii.hexlify(upxheader))

        # now search for a duplicate UPX header
        i = 1
        upxrange = elf
        while i == 1:
            lastupx = upxrange
            # found a match, but is it a header?
            upx = mm.find(UPX, lastupx)
            upxrange = mm.find(UPX, upx + 1)
            if (upxrange == (upx + 8)):
                mm.seek(upxrange)
                upxheaderdup = mm.read(40)
                print("Duplicate UPX header", binascii.hexlify(upxheaderdup))

                # copy the blocksize
                blocksize = upxheaderdup[24:27]
                print("Original blocksize: ", binascii.hexlify(upxheader[12:15]))
                print("Duplicate blocksize: ", binascii.hexlify(blocksize))
                # write the blocksize over the original header
                mm.seek(upxhdr + 12)
                mm.write(blocksize)
                mm.seek(upxhdr + 16)
                mm.write(blocksize)
            if upx == lastupx:
                break

        # Fix up UPX name TODO
        print("Suspected UPX magic:", upxheader[0:3])
        if UPX == upxheader[0:4]:
            print("UPX Magic matches, no need to edit it")
        else:
            print("Giving the UPX header its magic back")
            mm.seek(upxhdr)
            mm.write(UPX)


def main():
    parser = argparse.ArgumentParser(prog='unob')
    parser.add_argument('-i', dest='inputfile')
    args = parser.parse_args()

    if args.inputfile:
        # open and mmap our executable
        fp = open(args.inputfile, 'rb+')
        mm = mmap.mmap(fp.fileno(), 0)
        if (mm.find(UPX) == -1):
            print("Executable does not appear to be packed with UPX")
            return -1

        if PE32 in magic.from_file(args.inputfile):
            processPE(args.inputfile)
        elif ELF in magic.from_file(args.inputfile):
            processELF(mm)
        else:
            raise Exception("This file format is not supported")
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()