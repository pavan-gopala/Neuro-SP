from setuptools import setup, find_packages

setup(
    name="neuro-sp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "python-dotenv",
    ],
    entry_points={
        "console_scripts": [
            "neuro-scan=agents.sentinel.scanner:main",
        ],
    },
)