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

import requests

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
def add_read_parser(parser):
    pass

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
        add_read_parser(subparsers.add_parser(
                'read', help='pretty print ndef data'))

        self.rdwr_commands = {"read": self.read_tag,}
    
        super(TagTool, self).__init__(
            parser, groups="rdwr card dbg clf")

    def on_card_startup(self, target):
        pass

    def on_rdwr_startup(self, targets):
        if self.options.command in self.rdwr_commands.keys():
            print("** Waiting for tag to be presented **", file=sys.stderr)
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

    def read_tag(self, tag):
        print(tag)
        if tag.ndef:
            if tag.ndef.length > 0:
                print("Tag message:")
                print(tag.ndef.message.data()) # tag.ndef.message.data() is what you'll send in the POST body
                # r = requests.post('http://localhost:8080/api/smartKitchen/', data = {'readerId:', 'id-goes-here'})
        
        if self.options.verbose:
            print("Memory Dump:")
            print('  ' + '\n  '.join(tag.dump()))

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
        sys.argv = sys.argv + ['read']

    try:
        TagTool().run()
    except ArgparseError as e:
        print(e, file=sys.stderr)
