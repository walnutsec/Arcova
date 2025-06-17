import sys
if sys.platform == 'win32':
    import distutils.cygwinccompiler
    distutils.cygwinccompiler.get_msvcr = lambda: []
from setuptools import setup, Extension
import pybind11
import os

os.environ["CC"] = "g++"
os.environ["CXX"] = "g++"

ext_modules = [
    Extension(
        "f5_stego",
        ["f5_stego_binding.cpp", "F5steg.cpp"],
        include_dirs=[
            pybind11.get_include(),
            "C:/msys64/ucrt64/include",
            "C:/msys64/ucrt64/include/openssl"
        ],
        library_dirs=["C:/msys64/ucrt64/lib"],
        libraries=["jpeg", "ssl", "crypto"],
        extra_compile_args=["-std=c++17", "-Wall"],
        extra_link_args=["-static-libgcc", "-static-libstdc++"],
        language="c++"
    )
]

setup(
    name="f5_stego",
    ext_modules=ext_modules,
    zip_safe=False
)