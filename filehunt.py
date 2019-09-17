# -*- coding: UTF-8 -*-
"""
Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.

filehunt: general file searching library for use by PANhunt and PassHunt
By BB
"""

import os
import sys
import pickle
import zipfile
import re
import datetime
from io import StringIO
import unicodedata
import codecs
import colorama
import progressbar
import pst  # MS-PST files
import msmsg  # MS-MSG files

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024
TEXT_FILE_SIZE_LIMIT = GB


class AFile:
    """ AFile: class for a file that can search itself"""

    def __init__(self, filename, file_dir):
        self.filename = filename
        self.dir = file_dir
        self.path = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors = []
        self.type = None
        self.matches = []

    def set_file_stats(self):
        stat = os.stat(self.path)
        self.size = stat.st_size
        self.accessed = self.dtm_from_ts(stat.st_atime)
        self.modified = self.dtm_from_ts(stat.st_mtime)
        self.created = self.dtm_from_ts(stat.st_ctime)

    def dtm_from_ts(self, ts):
        try:
            return datetime.datetime.fromtimestamp(ts)
        except ValueError:
            self.set_error(sys.exc_info()[1])

    def check_text_regexs(self, text, regexs, sub_path):
        """Uses regular expressions to check for PANs in text"""
        from panhunt import PAN
        for brand, regex in regexs.items():
            pans = regex.findall(text)
            for pan in pans:
                if is_valid_luhn_checksum(pan) and not is_excluded(pan, []):
                    self.matches.append(PAN(self.path, sub_path, brand, pan))

    def size_friendly(self):
        return get_friendly_size(self.size)

    def set_error(self, error_msg):
        self.errors.append(error_msg)
        print(colorama.Fore.RED + 'ERROR %s on %s' % (error_msg, self.path) + colorama.Fore.WHITE)

    def check_regexs(self, regexs, search_extensions):
        """
        Checks the file for matching regular expressions:
            if a ZIP then each file in the ZIP (recursively)
            or the text in a document
        """
        if self.type == 'ZIP':
            try:
                if zipfile.is_zipfile(self.path):
                    zf = zipfile.ZipFile(self.path)
                    self.check_zip_regexs(zf, regexs, search_extensions, '')
                else:
                    self.set_error('Invalid ZIP file')
            except BaseException:
                self.set_error(sys.exc_info()[1])
        elif self.type == 'TEXT':
            try:
                file_text = read_file(self.path, 'rb')
                self.check_text_regexs(file_text, regexs, '')
            except BaseException:
                self.set_error(sys.exc_info()[1])

        elif self.type == 'SPECIAL':
            if get_ext(self.path) == '.msg':
                try:
                    msg = msmsg.MSMSG(self.path)
                    if msg.validMSG:
                        self.check_msg_regexs(msg, regexs, search_extensions, '')
                    else:
                        self.set_error('Invalid MSG file')
                    msg.close()
                except BaseException:
                    self.set_error(sys.exc_info()[1])

        return self.matches

    def check_pst_regexs(self, regexs, search_extensions,
                         hunt_type, gauge_update_function=None):
        """
        Searches a pst file for regular expressions
        in messages and attachments using regular expressions
        """
        if not gauge_update_function:
            pbar_widgets = [
                '%s Hunt %s: ' % (hunt_type, unicode2ascii(self.filename)),
                progressbar.Percentage(),
                ' ',
                progressbar.Bar(marker=progressbar.RotatingMarker()),
                ' ',
                progressbar.ETA(),
                progressbar.FormatLabel(' %ss:0' % hunt_type)
            ]
            pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
        else:
            gauge_update_function(caption='%s Hunt: ' % hunt_type)

        try:
            apst = pst.PST(self.path)
            if apst.header.validPST:

                total_messages = apst.get_total_message_count()
                total_attachments = apst.get_total_attachment_count()
                total_items = total_messages + total_attachments
                items_completed = 0

                for folder in apst.folder_generator():
                    for message in apst.message_generator(folder):
                        if message.Subject:
                            message_path = os.path.join(folder.path, message.Subject)
                        else:
                            message_path = os.path.join(folder.path, '[NoSubject]')
                        if message.Body:
                            self.check_text_regexs(message.Body, regexs, message_path)
                        if message.HasAttachments:
                            for subattachment in message.subattachments:
                                if get_ext(subattachment.Filename) in (search_extensions['TEXT'] +
                                                                       search_extensions['ZIP']):
                                    attachment = message.get_attachment(subattachment)
                                    self.check_attachment_regexs(attachment, regexs, search_extensions, message_path)
                                items_completed += 1
                        items_completed += 1
                        if not gauge_update_function:
                            pbar_widgets[6] = progressbar.FormatLabel(' %ss:%s' % (hunt_type, len(self.matches)))
                            pbar.update(items_completed * 100.0 / total_items)
                        else:
                            gauge_update_function(value=items_completed * 100.0 / total_items)

            apst.close()
        except BaseException:
            self.set_error(sys.exc_info()[1])

        if not gauge_update_function:
            pbar.finish()
        return self.matches

    def check_attachment_regexs(self, attachment, regexs, search_extensions, sub_path):
        """for PST and MSG attachments, check attachment for valid extension and then regexs"""

        attachment_ext = get_ext(attachment.Filename)
        if attachment_ext in search_extensions['TEXT']:
            if attachment.data:
                self.check_text_regexs(attachment.data, regexs, os.path.join(sub_path, attachment.Filename))

        if attachment_ext in search_extensions['ZIP']:
            if attachment.data:
                try:
                    memory_zip = StringIO()
                    memory_zip.write(attachment.data)
                    zf = zipfile.ZipFile(memory_zip)
                    self.check_zip_regexs(zf, regexs, search_extensions, os.path.join(sub_path, attachment.Filename))
                    memory_zip.close()
                except BaseException:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])

    def check_msg_regexs(self, msg, regexs, search_extensions, sub_path):

        if msg.Body:
            self.check_text_regexs(msg.Body, regexs, sub_path)
        if msg.attachments:
            for attachment in msg.attachments:
                self.check_attachment_regexs(attachment, regexs, search_extensions, sub_path)

    def check_zip_regexs(self, zf, regexs, search_extensions, sub_path):
        """Checks a zip file for valid documents that are then checked for regexs"""

        all_extensions = search_extensions['TEXT'] + search_extensions['ZIP'] + search_extensions['SPECIAL']

        files_in_zip = [file_in_zip for file_in_zip in zf.namelist() if get_ext(file_in_zip) in all_extensions]
        for file_in_zip in files_in_zip:
            if get_ext(file_in_zip) in search_extensions['ZIP']:  # nested zip file
                try:
                    memory_zip = StringIO()
                    memory_zip.write(zf.open(file_in_zip).read().decode('utf-8'))
                    nested_zf = zipfile.ZipFile(memory_zip)
                    self.check_zip_regexs(nested_zf, regexs, search_extensions,
                                          os.path.join(sub_path, decode_zip_filename(file_in_zip)))
                    memory_zip.close()
                except BaseException:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            elif get_ext(file_in_zip) in search_extensions['TEXT']:  # normal doc
                try:
                    file_text = zf.open(file_in_zip).read().decode('utf-8')
                    self.check_text_regexs(file_text, regexs, os.path.join(sub_path, decode_zip_filename(file_in_zip)))
                except BaseException:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            else:  # SPECIAL
                try:
                    if get_ext(file_in_zip) == '.msg':
                        memory_msg = StringIO()
                        memory_msg.write(zf.open(file_in_zip).read().decode('utf-8'))
                        msg = msmsg.MSMSG(memory_msg)
                        if msg.validMSG:
                            self.check_msg_regexs(msg, regexs, search_extensions,
                                                  os.path.join(sub_path, decode_zip_filename(file_in_zip)))
                        memory_msg.close()
                except BaseException:  # RuntimeError
                    self.set_error(sys.exc_info()[1])


def cmp(a_inc, b_inc):
    return (a_inc > b_inc) - (a_inc < b_inc)


def find_all_files_in_dir(a_file_class, root_dir, excluded_directories,
                          search_extensions, gauge_update_function=None):
    """
    Recursively searches a directory for files.
    Search_extensions is a dictionary of extension lists
    """
    all_extensions = [ext
                      for ext_list in search_extensions.values()
                      for ext in ext_list]

    extension_types = {}
    for ext_type, ext_list in search_extensions.items():
        for ext in ext_list:
            extension_types[ext] = ext_type

    if not gauge_update_function:
        pbar_widgets = ['Doc Hunt: ', progressbar.Percentage(),
                        ' ',
                        progressbar.Bar(marker=progressbar.RotatingMarker()),
                        ' ',
                        progressbar.ETA(), progressbar.FormatLabel(' Docs:0')
                        ]
        pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
    else:
        gauge_update_function(caption='Doc Hunt: ')

    doc_files = []
    root_dir_dirs = None
    root_items_completed = 0
    docs_found = 0

    for root, sub_dirs, files in os.walk(root_dir):
        sub_dirs[:] = [check_dir for check_dir in sub_dirs
                       if os.path.join(root, check_dir).lower() not in excluded_directories]
        if not root_dir_dirs:
            root_dir_dirs = [os.path.join(root, sub_dir) for sub_dir in sub_dirs]
            root_total_items = len(root_dir_dirs) + len(files)
        if root in root_dir_dirs:
            root_items_completed += 1
            if not gauge_update_function:
                pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
                pbar.update(root_items_completed * 100.0 / root_total_items)
            else:
                gauge_update_function(value=root_items_completed * 100.0 / root_total_items)
        for filename in files:
            if root == root_dir:
                root_items_completed += 1
            afile = a_file_class(filename, root)  # a_file or PANFile
            if afile.ext.lower() in all_extensions:
                afile.set_file_stats()
                afile.type = extension_types[afile.ext.lower()]
                if afile.type in ('TEXT', 'SPECIAL') and afile.size > TEXT_FILE_SIZE_LIMIT:
                    afile.type = 'OTHER'
                    afile.set_error('File size {1} over limit of {0} for checking'.format(
                        get_friendly_size(TEXT_FILE_SIZE_LIMIT), afile.size_friendly()))
                doc_files.append(afile)
                if not afile.errors:
                    docs_found += 1
                if not gauge_update_function:
                    pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
                    pbar.update(root_items_completed * 100.0 / root_total_items)
                else:
                    gauge_update_function(value=root_items_completed * 100.0 / root_total_items)

    if not gauge_update_function:
        pbar.finish()
    return doc_files


def find_all_regexs_in_files(text_or_zip_files, regexs, search_extensions, hunt_type, gauge_update_function=None):
    """ Searches files in doc_files list for regular expressions"""

    if not gauge_update_function:
        pbar_widgets = ['%s Hunt: ' % hunt_type, progressbar.Percentage(),
                        ' ',
                        progressbar.Bar(marker=progressbar.RotatingMarker()),
                        ' ',
                        progressbar.ETA(), progressbar.FormatLabel(' %ss:0' % hunt_type)
                        ]
        pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
    else:
        gauge_update_function(caption='%s Hunt: ' % hunt_type)

    total_files = len(text_or_zip_files)
    files_completed = 0
    matches_found = 0

    for afile in text_or_zip_files:
        matches = afile.check_regexs(regexs, search_extensions)
        matches_found += len(matches)
        files_completed += 1
        if not gauge_update_function:
            pbar_widgets[6] = progressbar.FormatLabel(' %ss:%s' % (hunt_type, matches_found))
            pbar.update(files_completed * 100.0 / total_files)
        else:
            gauge_update_function(value=files_completed * 100.0 / total_files)

    if not gauge_update_function:
        pbar.finish()

    return total_files, matches_found


def find_all_regexs_in_psts(pst_files, regexs, search_extensions, hunt_type, gauge_update_function=None):
    """ Searches psts in pst_files list for regular expressions in messages and attachments"""

    total_psts = len(pst_files)
    psts_completed = 0
    matches_found = 0

    for afile in pst_files:
        matches = afile.check_pst_regexs(regexs, search_extensions, hunt_type, gauge_update_function)
        matches_found += len(matches)
        psts_completed += 1

    return total_psts, matches_found


def is_excluded(pan, excluded_pans):
    for excluded_pan in excluded_pans:
        if pan == excluded_pan:
            return True
    return False


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


def save_object(file_, obj):
    pkl_file = open(file_, 'wb')
    pickle.dump(obj, pkl_file, -1)
    pkl_file.close()


def load_object(file_):
    pkl_file = open(file_, 'rb')
    obj = pickle.load(pkl_file)
    pkl_file.close()
    return obj


def read_file(file_, open_mode="r"):
    f_read = open(file_, open_mode)
    str_ = f_read.read().decode('utf-8')
    f_read.close()
    return str_


def write_file(file_, str_):
    f_write = open(file_, "w")
    f_write.write(str_)
    f_write.close()


def read_unicode_file(file_):
    f_read = codecs.open(file_, encoding='utf-8', mode='r')
    str_ = f_read.read()
    f_read.close()
    return str_


def write_unicode_file(file_, unicode_str):
    f_unicode = codecs.open(file_, encoding='utf-8', mode='w')
    f_unicode.write(unicode_str)
    f_unicode.close()


def write_csv(file_, dlines):
    f_csv = open(file_, "w")
    for dline in dlines:
        csv_string = ','.join(['"%s"' % str(i).replace('"', "'")
                               for i in dline])
        f_csv.write('%s\n' % csv_string)
    f_csv.close()


def unicode2ascii(unicode_str):
    return unicodedata.normalize('NFKD', unicode_str).encode('ascii', 'ignore')


def decode_zip_filename(str_):
    if isinstance(str_, str):
        return str_
    return str_.decode('cp437')


def get_ext(file_name):
    return os.path.splitext(file_name)[1].lower()


def get_friendly_size(size):
    if size < KB:
        return '{0}B'.format(size)
    if size < MB:
        return '{0}KB'.format(size / KB)
    if size < GB:
        return '{0}MB'.format(size / GB)
    return '{0:.1f}GB'.format(size * 1.0 / GB)
