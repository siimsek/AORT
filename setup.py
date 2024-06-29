from setuptools import setup, find_packages

setup(
    name='aort',
    version='2.0',
    description='All in One Recon Tool',
    author='siimsek',
    author_email='malisimsek17@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests',
        'dnspython',
        'pydig',
        'urllib3',
        'whois',
        'Wappalyzer',
    ],
    entry_points={
        'console_scripts': [
            'aort=aort.aort:main',
        ],
    },
    package_data={
        'aort': ['utils/*.json'],
    },
)