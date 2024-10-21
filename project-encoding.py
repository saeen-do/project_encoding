#!/usr/bin/python3

import base64
import binascii
import hashlib
import codecs
from urllib.parse import quote, unquote
from termcolor import colored
from pyfiglet import Figlet

def print_banner():
    figlet = Figlet(font='slant')
    print(colored(figlet.renderText('Encode/Decode Tool'), 'blue'))

def print_usage():
    print(colored("Usage: -e/-d -b64/-b32/-hex/-rot13/-url/-md5/-sha1/-sha224/-sha256/-sha384/-sha512/-crc32 text", 'cyan'))
    print("  -e: encode")
    print("  -d: decode")
    print("  -b64: Base64")
    print("  -b32: Base32")
    print("  -hex: Hexadecimal")
    print("  -rot13: ROT13")
    print("  -url: URL encoding")
    print("  -md5: MD5 hashing")
    print("  -sha1: SHA-1 hashing")
    print("  -sha224: SHA-224 hashing")
    print("  -sha256: SHA-256 hashing")
    print("  -sha384: SHA-384 hashing")
    print("  -sha512: SHA-512 hashing")
    print("  -crc32: CRC32 hashing")
    print(colored("Type 'exit' to quit.", 'yellow'))

def crc32_hash(text):
    return format(binascii.crc32(text.encode()) & 0xFFFFFFFF, '08x')

def process_command(command):
    parts = command.split()
    if len(parts) < 3:
        print(colored("Invalid command.", 'red'))
        print_usage()
        return

    action = parts[0]
    encoding = parts[1]
    text = " ".join(parts[2:])

    if action not in ["-e", "-d"]:
        print(colored("Invalid action. Use -e for encode or -d for decode.", 'red'))
        print_usage()
        return

    if encoding not in ["-b64", "-b32", "-hex", "-rot13", "-url", "-md5", "-sha1", "-sha224", "-sha256", "-sha384", "-sha512", "-crc32"]:
        print(colored("Invalid encoding type.", 'red'))
        print_usage()
        return

    try:
        if action == "-e":
            if encoding == "-b64":
                result = base64.b64encode(text.encode()).decode()
            elif encoding == "-b32":
                result = base64.b32encode(text.encode()).decode()
            elif encoding == "-hex":
                result = binascii.hexlify(text.encode()).decode()
            elif encoding == "-rot13":
                result = codecs.encode(text, 'rot_13')
            elif encoding == "-url":
                result = quote(text)
            elif encoding == "-md5":
                result = hashlib.md5(text.encode()).hexdigest()
            elif encoding == "-sha1":
                result = hashlib.sha1(text.encode()).hexdigest()
            elif encoding == "-sha224":
                result = hashlib.sha224(text.encode()).hexdigest()
            elif encoding == "-sha256":
                result = hashlib.sha256(text.encode()).hexdigest()
            elif encoding == "-sha384":
                result = hashlib.sha384(text.encode()).hexdigest()
            elif encoding == "-sha512":
                result = hashlib.sha512(text.encode()).hexdigest()
            elif encoding == "-crc32":
                result = crc32_hash(text)
        elif action == "-d":
            if encoding == "-b64":
                result = base64.b64decode(text).decode()
            elif encoding == "-b32":
                result = base64.b32decode(text).decode()
            elif encoding == "-hex":
                result = binascii.unhexlify(text).decode()
            elif encoding == "-rot13":
                result = codecs.encode(text, 'rot_13')
            elif encoding == "-url":
                result = unquote(text)
        
        print(colored(result, 'green'))
    except Exception as e:
        print(colored(f"Error: {e}", 'red'))

if __name__ == "__main__":
    print_banner()
    print_usage()
    while True:
        try:
            command = input(colored("Enter command: ", 'yellow'))
            if command.lower() == "exit":
                print(colored("Exiting the tool.", 'blue'))
                break
            process_command(command)
        except KeyboardInterrupt:
            print(colored("\nExiting the tool.", 'blue'))
            break
