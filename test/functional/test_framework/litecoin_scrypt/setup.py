from setuptools import setup, Extension
import os

HERE = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))  # from test/functional/test_framework/litecoin_scrypt

ext = Extension(
    "litecoin_scrypt._litecoin_scrypt",
    sources=[
        os.path.join(HERE, "litecoin_scrypt", "_litecoin_scrypt.cpp"),
        os.path.join(REPO_ROOT, "src", "crypto", "scrypt.cpp"),
        os.path.join(REPO_ROOT, "src", "crypto", "sha256.cpp"),
    ],
    include_dirs=[
        os.path.join(REPO_ROOT, "src"),
        os.path.join(REPO_ROOT, "src", "crypto"),
    ],
    libraries=["crypto"],
    language="c++",
    extra_compile_args=["-std=c++17"],
)


setup(
    name="litecoin_scrypt",
    version="0.0.0",
    packages=["litecoin_scrypt"],
    ext_modules=[ext],
)
