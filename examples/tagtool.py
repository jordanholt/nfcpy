#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
from __future__ import print_function

import logging
log = logging.getLogger('main')

import sys
import time
import string
import struct
import argparse
import hmac, hashlib

from cli import CommandLineInterface

import nfc
import nfc.clf
import nfc.ndef

def parse_version(string):
    try: major_version, minor_version = map(int, string.split('.'))
    except ValueError, AttributeError:
        msg = "%r is not a version string, expecting <int>.<int>"
        raise argparse.ArgumentTypeError(msg % string)
    if major_version < 0 or major_version > 15:
        msg = "major version %r is out of range, expecting 0...15"
        raise argparse.ArgumentTypeError(msg % major_version)
    if minor_version < 0 or minor_version > 15:
        msg = "minor version %r is out of range, expecting 0...15"
        raise argparse.ArgumentTypeError(msg % minor_version)
    return major_version << 4 | minor_version

def parse_uint8(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as an 8-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

def parse_uint16(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xffff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as a 16-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

def parse_uint24(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xffffff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as a 24-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

#
# command parsers
#
def add_show_parser(parser):
    pass

def add_dump_parser(parser):
    parser.add_argument(
        "-o", dest="output", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save ndef to FILE (writes binary data)")
        
def add_load_parser(parser):
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        help="ndef data file ('-' reads from stdin)")
        
def add_emulate_parser(parser):
    parser.description = "Emulate an ndef tag."    
    parser.add_argument(
        "-l", "--loop", action="store_true",
        help="continue (restart) after tag release")
    parser.add_argument(
        "-k", "--keep", action="store_true",
        help="keep tag memory (when --loop is set)")
    parser.add_argument(
        "-s", dest="size", type=int, default="1024",
        help="minimum ndef data area size (default: %(default)s)")
    parser.add_argument(
        "-p", dest="preserve", metavar="FILE", type=argparse.FileType('wb'),
        help="preserve tag memory when released")
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        nargs="?", default=None,
        help="ndef message to serve ('-' reads from stdin)")
    subparsers = parser.add_subparsers(title="Tag Types", dest="tagtype")
    add_emulate_tt3_parser(subparsers.add_parser(
            'tt3', help='emulate a type 3 tag'))
    
def add_emulate_tt3_parser(parser):
    parser.add_argument(
        "--idm", metavar="HEX", default="03FEFFE011223344",
        help="manufacture identifier (default: %(default)s)")
    parser.add_argument(
        "--pmm", metavar="HEX", default="01E0000000FFFF00",
        help="manufacture parameter (default: %(default)s)")
    parser.add_argument(
        "--sys", "--sc", metavar="HEX", default="12FC",
        help="system code (default: %(default)s)")
    parser.add_argument(
        "--bitrate", choices=["212", "424"], default="212",
        help="bitrate to listen (default: %(default)s)")
    parser.add_argument(
        "--ver", metavar="x.y", type=parse_version, default="1.0",
        help="ndef mapping version number (default: %(default)s)")
    parser.add_argument(
        "--nbr", metavar="INT", type=int, default=1,
        help="max read blocks at once (default: %(default)s)")
    parser.add_argument(
        "--nbw", metavar="INT", type=int, default=1,
        help="max write blocks at once (default: %(default)s)")
    parser.add_argument(
        "--max", metavar="INT", type=int,
        help="maximum number of blocks (default: computed)")
    parser.add_argument(
        "--rfu", metavar="INT", type=int, default=0,
        help="value to set for reserved bytes (default: %(default)s)")
    parser.add_argument(
        "--wf", metavar="INT", type=int, default=0,
        help="write-flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--rw", metavar="INT", type=int, default=1,
        help="read-write flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--crc", metavar="INT", type=int,
        help="checksum attribute value (default: computed)")

class TagTool(CommandLineInterface):
    def __init__(self):
        parser = ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="")
        parser.add_argument(
            "-p", dest="authenticate", metavar="PASSWORD",
            help="unlock with password if supported")
        subparsers = parser.add_subparsers(
            title="commands", dest="command")
        add_show_parser(subparsers.add_parser(
                'show', help='pretty print ndef data'))
        add_dump_parser(subparsers.add_parser(
                'dump', help='read ndef data from tag'))
        add_load_parser(subparsers.add_parser(
                'load', help='write ndef data to tag'))
        add_emulate_parser(subparsers.add_parser(
                'emulate', help='emulate an ndef tag'))

        self.rdwr_commands = {"show": self.show_tag,
                              "dump": self.dump_tag,
                              "load": self.load_tag,}
    
        super(TagTool, self).__init__(
            parser, groups="rdwr card dbg clf")

    def on_rdwr_startup(self, targets):
        if self.options.command in self.rdwr_commands.keys():
            print("** waiting for a tag **", file=sys.stderr)
            return targets

    def on_rdwr_connect(self, tag):
        if self.options.authenticate is not None:
            if len(self.options.authenticate) > 0:
                key, msg = self.options.authenticate, tag.identifier
                password = hmac.new(key, msg, hashlib.sha256).digest()
            else:
                password = "" # use factory default password
            result = tag.authenticate(password)
            if result is False:
                print("I'm sorry, but authentication failed.")
                return False
            if result is None:
                print(tag)
                print("I don't know how to authenticate this tag.")
                return False
            
        self.rdwr_commands[self.options.command](tag)
        return self.options.wait or self.options.loop
    
    def on_card_startup(self, target):
        if self.options.command == "emulate":
            target = self.prepare_tag(target)
            print("** waiting for a reader **", file=sys.stderr)
            return target

    def on_card_connect(self, tag):
        log.info("tag activated")
        return self.emulate_tag_start(tag)

    def on_card_release(self, tag):
        log.info("tag released")
        self.emulate_tag_stop(tag)
        return True

    def show_tag(self, tag):
        print(tag)
        
        if tag.ndef:
            print("NDEF Capabilities:")
            print("  readable  = %s" % ("no","yes")[tag.ndef.is_readable])
            print("  writeable = %s" % ("no","yes")[tag.ndef.is_writeable])
            print("  capacity  = %d byte" % tag.ndef.capacity)
            print("  message   = %d byte" % tag.ndef.length)
            if tag.ndef.length > 0:
                print("NDEF Message:")
                print(tag.ndef.message.pretty())
        
        if self.options.verbose:
            print("Memory Dump:")
            print('  ' + '\n  '.join(tag.dump()))

    def dump_tag(self, tag):
        if tag.ndef:
            data = tag.ndef.message
            if self.options.output.name == "<stdout>":
                self.options.output.write(str(data).encode("hex"))
                if self.options.loop:
                    self.options.output.write('\n')
                else:
                    self.options.output.flush()
            else:
                self.options.output.write(str(data))

    def load_tag(self, tag):
        try: self.options.data
        except AttributeError:
            self.options.data = self.options.input.read()
            try: self.options.data = self.options.data.decode("hex")
            except TypeError: pass

        if tag.ndef is None:
            print("This is not an NDEF Tag.")
            return

        if not tag.ndef.is_writeable:
            print("This Tag is not writeable.")
            return

        new_ndef_message = nfc.ndef.Message(self.options.data)
        if new_ndef_message == tag.ndef.message:
            print("The Tag already contains the message to write.")
            return

        if len(str(new_ndef_message)) > tag.ndef.capacity:
            print("The new message exceeds the Tag's capacity.")
            return
        
        print("Old message:")
        print(tag.ndef.message.pretty())
        tag.ndef.message = new_ndef_message
        print("New message:")
        print(tag.ndef.message.pretty())

    def prepare_tag(self, target):
        if self.options.tagtype == "tt3":
            return self.prepare_tt3_tag(target)

    def prepare_tt3_tag(self, target):
        if self.options.size % 16 != 0:
            self.options.size = ((self.options.size + 15) // 16) * 16
            log.warning("tt3 ndef data area size rounded to {0}"
                        .format(self.options.size))

        try: self.options.data
        except AttributeError:
            if self.options.input:
                self.options.data = self.options.input.read()
                try: self.options.data = self.options.data.decode("hex")
                except TypeError: pass
            else:
                self.options.data = ""

        if not (hasattr(self.options, "tt3_data") and self.options.keep):
            if self.options.input:
                ndef_data_size = len(self.options.data)
                ndef_area_size = ((ndef_data_size + 15) // 16) * 16
                ndef_area_size = max(ndef_area_size, self.options.size)
                ndef_data_area = bytearray(self.options.data) + \
                                 bytearray(ndef_area_size - ndef_data_size)
            else:
                ndef_data_area = bytearray(self.options.size)

            # create attribute data
            attribute_data = bytearray(16)
            attribute_data[0] = self.options.ver
            attribute_data[1] = self.options.nbr
            attribute_data[2] = self.options.nbw
            if self.options.max is None:
                nmaxb = len(ndef_data_area) // 16
            else: nmaxb = self.options.max
            attribute_data[3:5] = struct.pack(">H", nmaxb)
            attribute_data[5:9] = 4 * [self.options.rfu]
            attribute_data[9] = self.options.wf
            attribute_data[10:14] = struct.pack(">I", len(self.options.data))
            attribute_data[10] = self.options.rw
            attribute_data[14:16] = struct.pack(">H", sum(attribute_data[:14]))
            self.options.tt3_data = attribute_data + ndef_data_area

        idm = bytearray.fromhex(self.options.idm)
        pmm = bytearray.fromhex(self.options.pmm)
        sys = bytearray.fromhex(self.options.sys)

        target.brty = str(self.options.bitrate) + "F"
        target.sensf_res = "\x01" + idm + pmm + sys
        return target

    def emulate_tag_start(self, tag):
        if self.options.tagtype == "tt3":
            return self.emulate_tt3_tag(tag)

    def emulate_tag_stop(self, tag):
        if self.options.preserve:
            self.options.preserve.seek(0)
            self.options.preserve.write(self.options.tt3_data)
            log.info("wrote tag memory to file '{0}'"
                     .format(self.options.preserve.name))

    def emulate_tt3_tag(self, tag):
        def ndef_read(block_number, rb, re):
            log.debug("tt3 read block #{0}".format(block_number))
            if block_number < len(self.options.tt3_data) / 16:
                first, last = block_number*16, (block_number+1)*16
                block_data = self.options.tt3_data[first:last]
                return block_data
        def ndef_write(block_number, block_data, wb, we):
            log.debug("tt3 write block #{0}".format(block_number))
            if block_number < len(self.options.tt3_data) / 16:
                first, last = block_number*16, (block_number+1)*16
                self.options.tt3_data[first:last] = block_data
                return True

        tag.add_service(0x0009, ndef_read, ndef_write)
        tag.add_service(0x000B, ndef_read, lambda: False)
        return True

class ArgparseError(SystemExit):
    def __init__(self, prog, message):
        super(ArgparseError, self).__init__(2, prog, message)
    
    def __str__(self):
        return '{0}: {1}'.format(self.args[1], self.args[2])

class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgparseError(self.prog, message)

if __name__ == '__main__':
    try:
        TagTool().run()
    except ArgparseError as e:
        prog = e.args[1].split()
    else:
        sys.exit(0)

    if len(prog) == 1:
        sys.argv = sys.argv + ['show']
    elif prog[-1] == "format":
        sys.argv = sys.argv + ['any']

    try:
        TagTool().run()
    except ArgparseError as e:
        print(e, file=sys.stderr)
