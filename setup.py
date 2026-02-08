"""Setup script for agent-sandbox."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="agent-sandbox",
    version="0.1.0",
    author="BabyChrist666",
    author_email="babychrist666@example.com",
    description="Secure code execution environment for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BabyChrist666/agent-sandbox",
    packages=find_packages(exclude=["tests", "tests.*", "experiments", "docs"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "agent-sandbox=agent_sandbox.cli:main",
        ],
    },
)
