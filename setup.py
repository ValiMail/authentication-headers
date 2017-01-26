import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "authentication-headers",
    version = "0.5",
    author = "Gene Shuman",
    author_email = "gene@valimail.com",
    description = ("A library wrapping email authentication header verification and generation."),
    license = "MIT",
    keywords = "email headers SPF DKIM DMARC ARC",
    url = "",
    packages=['authentication-headers', 'tests'],
    long_description=read('README'),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires = [
        "py3dns",
        "pyspf",
        "dkimpy>=0.6.0",
        "authentication-results",        
    ],
)
