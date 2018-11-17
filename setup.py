from setuptools import setup

setup(
    name = "authheaders",
    version = "0.9.2",
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
    dependency_links = ['http://github.com/ValiMail/dkimpy/tarball/master#egg=dkimpy-0.7.1'
    ],
    install_requires = [
        "valimail_dkimpy>=0.7.1",
        "authres>=1.0.1",
        "publicsuffix",
        "ipaddress",
        "dnspython"
    ],
)
