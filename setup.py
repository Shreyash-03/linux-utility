#!/usr/bin/env python3
"""
Setup script for linux-sec-audit package installation.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="linux-sec-audit",
    version="1.0.0",
    author="Shreyash-03",
    author_email="",
    description="A comprehensive Linux security auditing CLI tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Shreyash-03/linux-utility",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "secscan=secscan.main:main",
        ],
    },
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pylint>=2.0",
        ],
    },
)
