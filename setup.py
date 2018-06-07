# -*- coding: utf-8 -*-
import os
from os.path import join, dirname, abspath
from setuptools import setup

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(join(abspath(__file__), os.pardir)))


def load_requirements(load_dependency_links=False):
    lines = open(join(dirname(__file__), 'requirements.txt')).readlines()
    requirements = []
    for line in lines:
        if 'https' in line and load_dependency_links:
            requirements.append(line)
        elif 'https' not in line and not load_dependency_links:
            requirements.append(line)
    return requirements


setup(
    author=u'Rafael Muñoz Cárdenas',
    author_email='rafael@humanitec.com',
    install_requires=load_requirements(),
    packages=[
        'oauth2_provider_jwt',
    ],
)
