from setuptools import setup, find_packages

setup(
    name='wireless_pen_test_lib',
    version='1.0.0',
    description='A library for wireless penetration testing',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/wireless_pen_test_lib',
    packages=find_packages(include=['wireless_pen_test_lib', 'wireless_pen_test_lib.*']),
    install_requires=[
        # List your dependencies here
    ],
    entry_points={
        'console_scripts': [
            'wptl-cli=wireless_pen_test_lib.ui.cli:main',
            'wptl-gui=wireless_pen_test_lib.ui.gui:main',
            # Add other entry points as needed
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)

