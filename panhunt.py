# -*- coding: UTF-8 -*-
"""
Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.

PANhunt: search directories and sub directories for documents with PANs
By BB
"""

import os
import sys
import re
import argparse
import time
import hashlib
import platform
import configparser
import colorama
import filehunt

APP_VERSION = '1.3'
PARAMS = {
    'outfile': 'panhunt_%s.txt' % time.strftime("%Y-%m-%d-%H%M%S"),
    'exclude': '/dev,/proc,/sys',
    'textfiles': '.doc,.xls,.xml,.txt,.csv,.log',
    'zipfiles': '.docx,.xlsx,.zip',
    'specialfiles': '.msg',
    'mailfiles': '.pst',
    'otherfiles': '.ost,.accdb,.mdb',
    'config_file': 'panhunt.ini'
}
PAN_REGEXS = {
    'Mastercard': re.compile(r'(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
    'Visa': re.compile(r'(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
    'AMEX': re.compile(r'(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')
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
    pan_report += 'Searched %s\nExcluded %s\n' % (params['search'], ','.join(prms['excluded_directories']))
    pan_report += 'Command: %s\n' % (' '.join(sys.argv))
    pan_report += 'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += 'Searched %s files. Found %s possible PANs.\n%s\n\n' % (total_searched, p_found, '=' * 100)

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

    pan_report = pan_report.replace('\n', os.linesep)

    print(colorama.Fore.WHITE + 'Report written to %s' % filehunt.unicode2ascii(output_file))
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)


def load_config_file(config_file):
    if not os.path.isfile(config_file):
        return dict()
    config = configparser.ConfigParser()
    config.read(config_file)
    return dict(config.defaults())


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
    # TODO: Rewrite main
    colorama.init()

    params = load_config_file(PARAMS.get('config_file', 'panhunt.ini'))
    params.update(PARAMS)
    arg_parser = argparse.ArgumentParser(
        prog='panhunt',
        description=f'PAN Hunt v{APP_VERSION}: search directories and sub directories for documents containing PANs.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    arg_parser.add_argument('-s', dest='search',
                            default=params['search'],
                            help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude',
                            default=params['exclude'],
                            help='directories to exclude from the search')
    arg_parser.add_argument('-t', dest='textfiles',
                            default=params['textfiles'],
                            help='text file extensions to search')
    arg_parser.add_argument('-z', dest='zipfiles',
                            default=params['zipfiles'],
                            help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='specialfiles',
                            default=params['specialfiles'],
                            help='special file extensions to search')
    arg_parser.add_argument('-m', dest='mailfiles',
                            default=params['mailfiles'],
                            help='email file extensions to search')
    arg_parser.add_argument('-l', dest='otherfiles',
                            default=params['otherfiles'],
                            help='other file extensions to list')
    arg_parser.add_argument('-o', dest='outfile',
                            default=params['outfile'],
                            help='output file name for PAN report')
    arg_parser.add_argument('-', dest='unmask', action='store_true',
                            default=False, help='unmask PANs in output')
    # arg_parser.add_argument('-C', dest='config',
    #                         default=PARAMS['config_file'],
    #                         help='configuration file to use')
    arg_parser.add_argument('-X', dest='excludepans',
                            default=params['excludepans'],
                            help='PAN to exclude from search')
    arg_parser.add_argument('-c', dest='checkfilehash', help=argparse.SUPPRESS)
    args = arg_parser.parse_args()

    if args.checkfilehash:
        check_file_hash(args.checkfilehash)
        sys.exit()
    args = dict(args.__dict__)
    params['mask_pans'] = not args.pop('unmask', None)
    params.update(args)

    search_ext = {
        'TEXT': params.pop('textfiles').split(','),
        'ZIP': params.pop('zipfiles').split(','),
        'SPECIAL': params.pop('specialfiles').split(','),
        'MAIL': params.pop('mailfiles').split(','),
        'OTHER': params.pop('otherfiles').split(','),
    }

    print(args)
    print(params)
    excluded_pans = params.get('excludepans', '').split(',')

    params['search_ext'] = search_ext
    total_files_searched, pans_found, all_files = hunt_pans(params)

    output_report(params, all_files, total_files_searched, pans_found)
