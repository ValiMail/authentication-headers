from setuptools import setup
import distutils.cmd
import distutils.log
import setuptools
import tempfile
import os
import sys
if sys.version_info[0] == 3:
  from urllib import request
else:
  import urllib as request

class UpdatePSDDMARCList(distutils.cmd.Command):
    """Update embedded copy of PSD DMARC participants list from psddmarc.org."""

    description = 'PSD DMARC update command - use prior to build/install commands'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Download to tempfile and move to authheaders/psddmarc.csv."""
        tmpfile = tempfile.mkstemp(".tmp", dir="./authheaders")[1]
        url = 'https://www.psddmarc.org/psddmarc-participants.csv'
        self.announce(
            'Updating PSD DMARC registry list',
            level=distutils.log.INFO)
        request.urlretrieve(url, tmpfile)
        os.rename(tmpfile, 'authheaders/psddmarc.csv')

class UpdatePublicSuffixList(distutils.cmd.Command):
    """Update embedded copy of PSL from publicsuffix.org."""

    description = 'PSL update command - use prior to build/install commands'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Download to tempfile and move to authheaders/public_suffix_list.txt."""
        tmpfile = tempfile.mkstemp(".tmp", dir="./authheaders")[1]
        url = 'https://publicsuffix.org/list/effective_tld_names.dat'
        self.announce(
            'Updating PSL',
            level=distutils.log.INFO)
        request.urlretrieve(url, tmpfile)
        os.rename(tmpfile, 'authheaders/public_suffix_list.txt')

class SetPSLLocation(distutils.cmd.Command):
    description = "Set location of system copy of PSL to use instead of embedded copy."
    user_options = [
        ('path=', None, 'Specify path to system PSL.'),
    ]

    def initialize_options(self):
        self.path = None

    def finalize_options(self):
        assert os.path.isfile(self.path) == True, 'Local public suffix list file does not exist'

    def run(self):
        f = open('authheaders/findpsl.py', 'w')
        f.write("location = '{0}'\r\n".format(self.path))
        f.close()


data = {
    'authheaders': ['public_suffix_list.txt'],
}
if sys.version_info[0] == 3:
    try:
        if os.path.getmtime('authheaders/findpsl.py') >= os.path.getmtime('setup.py'):
            data = {}
    except FileNotFoundError:
        pass
    try:
        if os.path.isfile('authheaders/psddmarc.csv') == True:
            if data == {}:
                data = {'authheaders': ['psddmarc.csv'],}
            else:
                data = {'authheaders': ['public_suffix_list.txt','psddmarc.csv'],}
    except FileNotFoundError:
        pass
else: # because the error is different in python2.7
    try:
        if os.path.getmtime('authheaders/findpsl.py') >= os.path.getmtime('setup.py'):
            data = {}
    except OSError:
        pass
    try:
        if os.path.isfile('authheaders/psddmarc.csv') == True:
            if data == {}:
                data = {'authheaders': ['psddmarc.csv'],}
            else:
                data = {'authheaders': ['public_suffix_list.txt','psddmarc.csv'],}
    except OSError:
        pass

# ipaddress in Python standard library python3.3 and later
requires=[
    "dkimpy>=0.7.1",
    "authres>=1.2.0",
    "publicsuffix2",
    "ipaddress",
    "dnspython"
]
if sys.version_info >= (3, 3):
    requires=[
        "dkimpy>=0.7.1",
        "authres>=1.2.0",
        "publicsuffix2",
        "dnspython"
    ]

# READM.md support instroduce in setuptools 36.4.0
if tuple(setuptools.__version__.split('.')) < ('36', '4', '0'):
    raise Exception('authheaders requires setuptools version 36.4.0 or later')

DESC = """Python module for generating email authentication headers: Authheaders can generate both authentication results header fields and DKIM/ ARC sighatures. It can perform DKIM, SPF, and DMARC validation, and the results are packaged into a single Authentication-Results header. It can also DKIM and ARC sign messages and output the corresponding signature header fields. """

setup(
    name = "authheaders",
    version = "0.14.0",
    author = "Gene Shuman",
    author_email = "gene@valimail.com",
    description = ("A library wrapping email authentication header verification and generation."),
    long_description=DESC,
    long_description_content_type='text/plain',
    license = "MIT",
    keywords = ["email", "headers", "SPF", "DKIM", "DMARC", "ARC"],
    url = "https://github.com/ValiMail/authentication-headers",
    zip_safe=False,
    packages=['authheaders'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Email :: Mail Transport Agents',
        'Topic :: Communications :: Email :: Filters',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    package_data=data,
    install_requires=requires,
    cmdclass={
        'psllocal': SetPSLLocation,
        'pslupdate': UpdatePublicSuffixList,
        'psddmarc': UpdatePSDDMARCList
    },
)
