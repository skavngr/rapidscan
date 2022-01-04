#! /usr/bin/env python3
from setuptools import setup

import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name                =   "rapidscan",
    version             =   '1.2',
    description         =   "The Multi-Tool Web Vulnerability Scanner.",
    long_description    =   README,
    long_description_content_type = "text/markdown",
    url                 =   "https://github.com/skavngr/rapidscan",
    author              =   "sh4nx0r",
    py_modules          =   ['rapidscan',],
    install_requires    =   [],
    python_requires=">=3.6",
)
