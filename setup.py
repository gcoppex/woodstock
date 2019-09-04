from setuptools import setup
import os, sys
# import woodstock

if sys.version_info < (3, 6,):
    raise Exception("axeman requires Python >= 3.5.")

with open('requirements.txt') as f:
    dependencies = f.read().splitlines()

setup(
    name='woodstock',
    version='1.0',
    url='https://github.com/gcoppex/Woodstock/',
    author='G. Coppex',
    install_requires=dependencies,
    description='Woodstock fetches and extracts the Certificate Transparency logs.',
    long_description="""
    Simple python program to extract and pre-process Certificate Transparency logs (CT logs).
    The output is either a list of CSV files or Parquet files, truncated by a constant batch size.
    The implementation takes advantage of each CPU cores (thanks to asyncio python library).
    """,
    packages=['woodstock'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'woodstock = woodstock.woodstock:main',
        ],
    },
    license = "The Unlicense",
    classifiers = [
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Console",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
)
