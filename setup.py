'''A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
'''

# To use a consistent encoding
from codecs import open as copen
from os import path

# Always prefer setuptools over distutils
from setuptools import setup

# Get the version
import kitools

# Get the long description from the README file
HERE = path.abspath(path.dirname(__file__))
with copen(path.join(HERE, 'README.rst'), encoding='utf-8') as _file:
    LONG_DESC = _file.read()

setup(
    name='kitools',
    # https://packaging.python.org/en/latest/single_source_version.html
    version=kitools.__version__,
    description='KiNOS interfacing tools',
    long_description=LONG_DESC,
    # The project's main homepage.
    url='https://github.com/KiraleTech/KiTools',
    # Author details
    author='Kirale Technologies',
    author_email='info@kirale.com',
    license='MIT',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Environment :: Console',
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Hardware',
        'Topic :: Terminals :: Serial',
        'Topic :: Utilities',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux'
    ],
    keywords='kinos serial tools',
    packages=['kitools'],
    include_package_data=True,
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['colorama', 'iptools', 'pyserial', 'pyusb', 'tqdm'],
    entry_points={
        'console_scripts': [
            'kitools = kitools.__main__:main'
        ]
    },
)
