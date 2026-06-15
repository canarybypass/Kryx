"""
Setup configuration for Kryx CLI
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="kryx",
    version="0.1.0",
    description="AI-powered security scanning CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Kryx Security",
    author_email="contact@kryx.io",
    url="https://kryx.io",
    packages=find_packages(),
    py_modules=["kryx_cli"],
    install_requires=[
        "click>=8.1.0",
        "httpx>=0.27.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "kryx=kryx_cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    keywords="security scanning vulnerabilities pentesting",
)
