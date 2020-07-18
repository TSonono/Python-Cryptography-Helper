import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as frq:
    requirements = frq.read().splitlines()

setuptools.setup(
    name="cryptography_bytes",
    version="0.0.1",
    author="Tofik Sonono",
    author_email="tofiksonono@msn.com",
    description="A package for interacting with python cryptography using bytes instead of asn1 structures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,

)
