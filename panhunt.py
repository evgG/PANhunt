# -*- coding: UTF-8 -*-
"""
Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.

PANhunt: search directories and sub directories for documents with PANs
By BB
"""

import os
import re
import time
import hashlib
import platform

import colorama

import filehunt

from config import load_config_file

APP_VERSION = '1.3'
PAN_REGEXS = {
    'Mastercard': re.compile(r'(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}'
                             r'(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
    'Visa': re.compile(r'(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}'
                       r'(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
    'AMEX': re.compile(r'(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}'
                       r'(?:\ |\-|)[0-9]{5})(?:\D|$)')
}


class PAN:
    """
    PAN: A class for recording PANs, their brand and where they were found
    """
    def __init__(self, path, sub_path, brand, pan):
        self.path = path
        self.sub_path = sub_path
        self.brand = brand
        self.pan = pan

    def __repr__(self, mask_pan=True):
        if mask_pan:
            return f'{self.sub_path} {self.brand}:{self.get_masked_pan()}'
        return f'{self.sub_path} {self.brand}:{self.pan}'

    def get_masked_pan(self):
        return re.sub(r'\d', '*', self.pan[:-4]) + self.pan[-4:]


def get_text_hash(text):
    if isinstance(text, str):
        return hashlib.sha512((text + 'PAN').encode('utf-8')).hexdigest()
    return hashlib.sha512(text + 'PAN').hexdigest()


def add_hash_to_file(text_file):
    # text = filehunt.read_unicode_file(text_file)
    text = open(text_file, 'r', encoding='utf-8').read()
    text += os.linesep + get_text_hash(text)
    filehunt.write_unicode_file(text_file, text)


def check_file_hash(text_file):
    text_output = filehunt.read_unicode_file(text_file)
    hash_pos = text_output.rfind(os.linesep)
    hash_in_file = text_output[hash_pos + len(os.linesep):]
    hash_check = get_text_hash(text_output[:hash_pos])
    if hash_in_file == hash_check:
        print(colorama.Fore.GREEN + 'Hashes OK')
    else:
        print(colorama.Fore.RED + 'Hashes Not OK')
        print(colorama.Fore.WHITE + hash_in_file + '\n' + hash_check)


def output_report(prms, all_f, total_searched, p_found):
    output_file = prms['outfile']
    pan_sep = '\n\t'
    pan_report = 'PAN Hunt Report - %s\n%s\n' % (time.strftime("%H:%M:%S %d/%m/%Y"), '=' * 100)
    pan_report += 'Searched %s\nExcluded %s\n' % (params['search'], ','.join(prms['exclude']))
    pan_report += 'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += f'Searched {total_searched} files. Found {p_found} possible PANs.\n{"=" * 100}\n\n'

    for afile in sorted([afile for afile in all_f if afile.matches]):
        pan_header = 'FOUND PANs: %s (%s %s)' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        print(colorama.Fore.RED + filehunt.unicode2ascii(pan_header))
        pan_report += pan_header + '\n'
        pan_list = '\t' + pan_sep.join([pan.__repr__(prms['mask_pans']) for pan in afile.matches])
        print(colorama.Fore.YELLOW + filehunt.unicode2ascii(pan_list))
        pan_report += pan_list + '\n\n'

    if [afile for afile in all_f if afile.type == 'OTHER']:
        pan_report += 'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in all_f if afile.type == 'OTHER']):
        pan_report += '%s (%s %s)\n' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    print(colorama.Fore.WHITE + 'Report written to %s' % filehunt.unicode2ascii(output_file))
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)


def hunt_pans(prms, gauge_update_function=None):
    search_dir = prms['search']
    excluded_directories = prms['exclude']
    search_extensions = prms['search_ext']
    all_f = filehunt.find_all_files_in_dir(filehunt.AFile, search_dir,
                                           excluded_directories,
                                           search_extensions,
                                           gauge_update_function)

    # check each file
    docs = [afile for afile in all_f
            if not afile.errors and afile.type in ('TEXT', 'ZIP', 'SPECIAL')]
    total_docs, doc_pans_found = filehunt.find_all_regexs_in_files(docs,
                                                                   PAN_REGEXS, search_extensions, 'PAN',
                                                                   gauge_update_function)
    # check each pst message and attachment
    psts = [afile for afile in all_f
            if not afile.errors and afile.type == 'MAIL']
    total_psts, pst_pans_found = filehunt.find_all_regexs_in_psts(psts,
                                                                  PAN_REGEXS, search_extensions, 'PAN',
                                                                  gauge_update_function)

    total_searched = total_docs + total_psts
    p_found = doc_pans_found + pst_pans_found

    return total_searched, p_found, all_f


if __name__ == "__main__":
    colorama.init()

    params = load_config_file()
    search_ext = {
        'TEXT': params.pop('textfiles'),
        'ZIP': params.pop('zipfiles'),
        'SPECIAL': params.pop('specialfiles'),
        'MAIL': params.pop('mailfiles'),
        'OTHER': params.pop('otherfiles'),
    }
    params['search_ext'] = search_ext

    excluded_pans = params.get('excludepans', None) or ''

    total_files_searched, pans_found, all_files = hunt_pans(params)

    output_report(params, all_files, total_files_searched, pans_found)
