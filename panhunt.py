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


def get_text_hash(text):
    if isinstance(text, str):
        return hashlib.sha512((text + 'PAN').encode('utf-8')).hexdigest()
    return hashlib.sha512(text + 'PAN').hexdigest()


def add_hash_to_file(text_file):
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
    pan_report += f'Total files: {all_f}. Searched {total_searched} files. '
    pan_report += f'Found {p_found} possible PANs.\n{"=" * 100}\n\n'

    for pan in p_found:
        pan_header = f'FOUND PANs: {pan["path"]} ({pan["filesize"]} {pan["modified"]}))'
        print(colorama.Fore.RED + pan_header)
        pan_report += pan_header + '\n'
        # pan_list = '\t' + pan_sep.join([pan.__repr__(prms['mask_pans']) for p in pan['pans']])
        pan_list = '\t' + pan_sep.join(pan['pans'])
        print(colorama.Fore.YELLOW + pan_list)
        pan_report += pan_list + '\n\n'

    print(colorama.Fore.WHITE + 'Report written to %s' % output_file)
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)


def hunt_pans(prms):
    search_dir = prms['search']
    excluded_directories = prms['exclude']
    all_f = filehunt.find_files(search_dir, excluded_directories)
    print(f'v2: {all_f}')
    docs = [item for k, v in all_f.items()
            if k.startswith('text/') for item in v]
    print(f'docs_v2: {len(docs)}')
    pan_list = filehunt.find_regexs_in_files(docs, PAN_REGEXS)
    print(f'total_docs_v2: {pan_list}')

    return docs, pan_list, all_f


if __name__ == "__main__":
    params = load_config_file()
    excluded_pans = params.get('excludepans', None) or ''
    colorama.init()
    total_files_searched, pans_found, all_files = hunt_pans(params)

    output_report(params, all_files, total_files_searched, pans_found)
