from setuptools import setup, find_packages

setup(
    name="recon_xtreme",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "httpx",
        "aiohttp",
        "rich",
        "typer",
        "asyncio",
        "beautifulsoup4",
        "pyyaml",
        "aiodns",
        "dnspython",
        "requests",
        "colorama",
        "cryptography",  # For SSL certificate analysis
        "python-dateutil"  # For timestamp handling
    ],
    entry_points={
        'console_scripts': [
            'recon-xtreme=main:app',
        ],
    },
)