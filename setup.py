# SPDX-License-Identifier: GPL-2.0+
#!/usr/bin/env python3
from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name='cloud-mdir-sync',
    version='1.0',
    description='Synchronize cloud mailboxes with a local MailDir',
    long_description=readme(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Operating System :: POSIX :: Linux',
        'Topic :: Communications :: Email :: Post-Office',
        'Classifier: License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 3.6',
    ],
    keywords="office365 email maildir",
    url='http://github.com/jgunthorpe',
    author='Jason Gunthorpe',
    author_email='jgg@ziepe.ca',
    license='GPL',
    packages=['cloud_mdir_sync'],
    entry_points={
        'console_scripts': ['cloud-mdir-sync=cloud_mdir_sync.main:main'],
    },
    python_requires=">=3.6",
    install_requires=[
        'aiohttp>=3.0.1',
        'cryptography>=2.8',
        'keyring>=21',
        'msal>=1.0',
        'pyinotify>=0.9.6',
        'requests>=2.18',
    ],
    include_package_data=True,
    zip_safe=False)
