from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="azshell",
    version="1.0",
    author="Víctor Rodríguez",
    author_email="vifreex@protonmail.com",
    description="Azure APIs enumeration and abuse",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    url="https://github.com/vifreex/AzShell",
    install_requires=[
        "msal",
        "cmd2",
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
        "License :: OSI Approved :: MIT License",
    ],
)