from setuptools import setup, find_packages
import sys

if sys.version_info < (3, 9):
    print("ERROR: AzShell requires Python >= 3.9")
    sys.exit(1)

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="azshell",
    version="1.2.1",
    author="Víctor Rodríguez",
    author_email="vifreex@protonmail.com",
    description="Azure APIs enumeration and abuse",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    url="https://github.com/vifreex/AzShell",
    python_requires=">=3.9",
    install_requires=[
        "msal",
        "cmd2==2.7.0",
        "argparse",
        "bs4"
    ],
    entry_points={
        "console_scripts": [
            "azshell = AzShell.main:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)
