from setuptools import setup
import distutils.cmd
import distutils.log
import setuptools
import tempfile
from urllib import request
import os

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

setup(
    name = "authheaders",
    version = "0.9.4",
    author = "Gene Shuman",
    author_email = "gene@valimail.com",
    description = ("A library wrapping email authentication header verification and generation."),
    license = "MIT",
    keywords = ["email", "headers", "SPF", "DKIM", "DMARC", "ARC"],
    url = "https://github.com/ValiMail/authentication-headers",
    packages=['authheaders'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
    package_data={
        'authheaders': ['public_suffix_list.txt'],
    },
    install_requires = [
        "dkimpy>=0.7.1",
        "authres>=1.0.1",
        "publicsuffix",
        "ipaddress",
        "dnspython"
    ],
    cmdclass={
        'pslupdate': UpdatePublicSuffixList,
    },
)
