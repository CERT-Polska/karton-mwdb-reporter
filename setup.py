#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/mwdb_reporter/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-mwdb-reporter",
    version=version_info["__version__"],
    description="Karton service that uploads analyzed artifacts "
                "and metadata to MWDB Core",
    namespace_packages=["karton"],
    packages=["karton.mwdb_reporter"],
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        'console_scripts': [
            'karton-mwdb-reporter=karton.mwdb_reporter:Reporter.main'
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ]
)
