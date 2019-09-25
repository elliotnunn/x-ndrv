#!/usr/bin/env python3

# This is going to be a slightly messy script. It rips all PEFs from the files that you pass it

import struct
import datetime


MAGIC = b'J o y ! p e f f'.replace(b' ', b'') # Conceal from an overzealous script


class PEF:
    CONT_HEAD_FMT = '>4s4s4s5I2HI'
    CONT_HEAD_LEN = struct.calcsize(CONT_HEAD_FMT)
    
    SEC_HEAD_FMT = '>i5I4B'
    SEC_HED_LEN = struct.calcsize(SEC_HEAD_FMT)

    def __init__(self, data):
        if not data.startswith(MAGIC): raise ValueError('not a pef')

        (magic, fourcc, arch, ver,
        timestamp, old_def_ver, old_imp_ver, cur_ver,
        sec_count, inst_sec_count, reserv) = struct.unpack_from(self.CONT_HEAD_FMT, data)

        sec_earliest = len(data)
        sec_latest = 0

        self.sections = []
        self.sectypes = []
        self.headeroffsets = []

        self.code = None

        for i in range(sec_count):
            sh_offset = self.CONT_HEAD_LEN + self.SEC_HED_LEN*i

            (sectionName, sectionAddress, execSize,
            initSize, rawSize, containerOffset,
            regionKind, shareKind, alignment, reserved) = struct.unpack_from(self.SEC_HEAD_FMT, data, sh_offset)

            the_sec = data[containerOffset : containerOffset + rawSize]

            if regionKind == 0 and execSize == initSize == rawSize:
                the_sec = bytearray(the_sec)
                self.code = the_sec

            self.sections.append(the_sec)
            self.sectypes.append(regionKind)
            self.headeroffsets.append(sh_offset)

            sec_earliest = min(sec_earliest, containerOffset)
            sec_latest = max(sec_latest, containerOffset + rawSize)

        if any(data[sec_latest:]):
            print('nonzero trailing data from', hex(sec_latest), 'to', hex(len(data)), ' ... will cause incorrect output')

        self.padmult = 1
        while len(data) % (self.padmult * 2) == 0:
            self.padmult *= 2

        self.header = data[:sec_earliest]

    def __bytes__(self):
        accum = bytearray(self.header)

        for i in range(len(self.sections)):
            the_sec = self.sections[i]
            hoff = self.headeroffsets[i]

            while len(accum) % 16:
                accum.append(0)

            new_off = len(accum)
            new_len = len(the_sec)

            accum.extend(the_sec)

            struct.pack_into('>I', accum, hoff + 20, new_off)

            if the_sec is self.code:
                for i in range(8, 20, 4):
                    struct.pack_into('>I', accum, hoff + i, new_len)

        while len(accum) % self.padmult != 0:
            accum.extend(b'\x00')

        return bytes(accum)


def pidata(packed):
    def pullarg(from_iter):
        arg = 0
        for i in range(4):
            cont = next(from_iter)
            arg <<= 7
            arg |= cont & 0x7f
            if not (cont & 0x80): break
        else:
            raise ValueError('arg spread over too many bytes')
        return arg

    packed = iter(packed)
    unpacked = bytearray()

    for b in packed:
        opcode = b >> 5
        arg = b & 0b11111 or pullarg(packed)

        if opcode == 0b000: # zero
            count = arg
            unpacked.extend(b'\0' * count)

        elif opcode == 0b001: # blockCopy
            blockSize = arg
            for i in range(blockSize):
                unpacked.append(next(packed))

        elif opcode == 0b010: # repeatedBlock
            blockSize = arg
            repeatCount = pullarg(packed) + 1
            rawData = bytes(next(packed) for n in range(blockSize))
            for n in range(repeatCount):
                unpacked.extend(rawData)

        elif opcode == 0b011 or opcode == 0b100: # interleaveRepeatBlockWithBlockCopy
            commonSize = arg                     # or interleaveRepeatBlockWithZero
            customSize = pullarg(packed)
            repeatCount = pullarg(packed)

            if opcode == 0b011:
                commonData = bytes(next(packed) for n in range(commonSize))
            else:
                commonData = b'\0' * commonSize

            for i in range(repeatCount):
                unpacked.extend(commonData)
                for j in range(customSize):
                    unpacked.append(next(packed))
            unpacked.extend(commonData)

        else:
            raise ValueError('unknown pidata opcode/arg %s/%d' % (bin(opcode), arg))
            return

    return bytes(unpacked)


def parse_version(num):
    maj, minbug, stage, unreleased = num.to_bytes(4, byteorder='big')

    maj = '%x' % maj
    minor, bugfix = '%02x' % minbug

    if stage == 0x80:
        stage = 'f'
    elif stage == 0x60:
        stage = 'b'
    elif stage == 0x40:
        stage = 'a'
    elif stage == 0x20:
        stage = 'd'
    else:
        stage = '?'

    unreleased = '%d' % unreleased

    vers = maj + '.' + minor

    if bugfix != '0':
        vers += '.' + bugfix

    if (stage, unreleased) != ('f', '0'):
        vers += stage + unreleased

    return vers


def pefdate(pef):
    srcint, = struct.unpack_from('>L', pef, 16)
    dt = datetime.datetime(1904, 1, 1) + datetime.timedelta(seconds=srcint)
    return dt.isoformat().replace('-', '').replace('T', '.').replace(':', '')


def suggest_name(pef):
    if not pef.startswith(MAGIC): return

    try:
        pef = PEF(pef)

        for sectype, section in zip(pef.sectypes, pef.sections):
            if sectype == 2: section = pidata(section)

            if section and sectype in (1, 2):
                hdr_ofs = section.find(b'mtej')
                if hdr_ofs != -1:
                    sig, strvers, devnam, drvvers = struct.unpack_from('>4s L 32p L', section, hdr_ofs)                

                    sugg = devnam.decode('mac_roman') + '-' + parse_version(drvvers)
                    return sugg
    except:
        pass # do not complain about corrupt PEFs



# COMMAND LINE INTERFACE (super simple)

import argparse
import os
import shutil
from os import path
import sys
import hashlib
import shlex


parser = argparse.ArgumentParser(description='''
    Rip all System 7-Mac OS 9 Code Fragments in a directory
    (to SRC/fragrip) or in a file (to SRC.fragrip)
''')

parser.add_argument('src', nargs='*', metavar='SRC', action='store', help='Source file/dir')

args = parser.parse_args()

def delete(x):
    try:
        shutil.rmtree(x)
    except:
        pass

    try:
        os.remove(x)
    except:
        pass


for src in args.src:
    if path.isdir(src):
        all_dir = path.join(src, 'fragrip')
        delete(all_dir)

        files = []
        for dirpath, dirnames, filenames in os.walk(src, followlinks=True):
            dirnames.sort(); filenames.sort()
            for filename in filenames:
                files.append(path.join(dirpath, filename))

    else:
        all_dir = src.rstrip(path.sep) + '.fragrip'
        delete(all_dir)

        files = [src]


    saved = {}
    for x in files:
        data = open(x, 'rb').read()

        pefs = [MAGIC+frag for frag in data.split(MAGIC)[1:]]

        for i, pef in enumerate(pefs, 1):
            os.makedirs(all_dir, exist_ok=True)

            if pef not in saved:
                filename = (suggest_name(pef) or hashlib.sha1(pef).hexdigest())
                filename += '-' + pefdate(pef)
                savednames = set(saved.values())
                if filename in savednames:
                    # print(filename)
                    filename += '-' + hashlib.sha1(pef).hexdigest()

                saved[pef] = filename

                open(path.join(all_dir, filename + '.pef'), 'wb').write(pef)

            filename = saved[pef]

            # Adjacent to each .pef, create a text file showing where it "came from"
            open(path.join(all_dir, filename + '.txt'), 'a').write('%s #%d/%d\n' % (shlex.quote(path.relpath(x, all_dir)), i, len(pefs)))

            # decompress the pidata segment
            # pefobj = PEF(pef)
            # while 2 in pefobj.sectypes:
            #     i = pefobj.sectypes.index(2)

            #     pefobj.sectypes[i] = 1
            #     pefobj.sections[i] = pidata(pefobj.sections[i])

            # open(dest[:-4] + '.xtr.pef', 'wb').write(bytes(pefobj))
