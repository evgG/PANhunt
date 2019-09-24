# -*- coding: UTF-8 -*-
"""
Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.

filehunt: general file searching library for use by PANhunt and PassHunt
By BB
"""

import codecs
from datetime import datetime
import os
import re

import magic

# import pst  # MS-PST files
# import msmsg  # MS-MSG files


KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024
TEXT_FILE_SIZE_LIMIT = GB


def find_files(root_dir, excluded_directories):
    """
    Recursively searches a directory for files.
    """
    doc_files = {}

    for root, _, files in os.walk(root_dir):
        if root in excluded_directories:
            continue
        for f in files:
            f_path = os.path.join(root, f)
            f_type = magic.from_file(f_path, mime=True)
            if f_type in doc_files.keys():
                doc_files[f_type].append(f_path)
            else:
                doc_files[f_type] = [f_path]
    return doc_files


def check_text_regexs(file_path, regexs, excluded):
    found_pans = []

    with open(file_path) as f:
        data = f.read()

    for _, regex in regexs.items():
        pans = regex.findall(data)
        found_pans += [pan
                       for pan in pans
                       if is_valid_luhn_checksum(pan) and pan not in excluded]
    return found_pans


def find_regexs_in_files(text_files, regexs, excluded_pans=None):
    """
    Searches files in text_files list for regular expressions
    """
    if excluded_pans is None:
        excluded_pans = []
    pans = []

    for afile in text_files:
        matches = check_text_regexs(afile, regexs, excluded_pans)
        if matches:
            size = os.path.getsize(afile)
            date = datetime.fromtimestamp(os.path.getmtime(afile))
            match = {'path': afile,
                     'pans': matches,
                     'filesize': get_friendly_size(size),
                     'modified': date.strftime('%d/%m/%Y'),
                     }
            pans.append(match)

    return pans


def is_valid_luhn_checksum(pan):
    """ from wikipedia: http://en.wikipedia.org/wiki/Luhn_algorithm"""
    pan = re.sub(r'[^\d]', '', pan)

    def digits_of(num):
        return [int(d) for d in str(num)]

    digits = digits_of(pan)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for digit in even_digits:
        checksum += sum(digits_of(digit * 2))

    return checksum % 10 == 0


def read_unicode_file(file_):
    f_read = codecs.open(file_, encoding='utf-8', mode='r')
    str_ = f_read.read()
    f_read.close()
    return str_


def write_unicode_file(file_, unicode_str):
    f_unicode = codecs.open(file_, encoding='utf-8', mode='w')
    f_unicode.write(unicode_str)
    f_unicode.close()


def get_friendly_size(size):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f'{size:3.1f} {x}'
        size /= 1024.0
    return f'File is too large'
