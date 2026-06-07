"""
Setup configuration for Hexor CLI
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="vulnyx",
    version="0.1.0",
    description="AI-powered security scanning CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Vulnyx Security",
    author_email="contact@vulnyx.io",
    url="https://vulnyx.io",
    packages=find_packages(),
    py_modules=["vulnyx_cli"],
    install_requires=[
        "click>=8.1.0",
        "httpx>=0.27.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnyx=vulnyx_cli:cli",
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
