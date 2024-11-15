# setup.py

from setuptools import setup, find_packages

setup(
    name='wireless_pen_test_lib',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'click',
        'PyYAML',
        'docker',
        'scapy',
        # Add other dependencies as needed
    ],
    entry_points={
        'console_scripts': [
            'wireless-pen-test=ui.cli:cli',
        ],
    },
)
