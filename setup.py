from distutils.core import setup

setup(
    name = "authentication-headers",
    version = "0.5",
    author = "Gene Shuman",
    author_email = "gene@valimail.com",
    description = ("A library wrapping email authentication header verification and generation."),
    license = "MIT",
    keywords = ["email", "headers", "SPF", "DKIM", "DMARC", "ARC"],
    url = "https://github.com/ValiMail/authentication-headers",
    packages=['authheaders', 'test'],
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
        "publicsuffix",
        "ipaddr",
    ],
)
