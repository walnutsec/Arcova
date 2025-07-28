# setup.py 
import os
import sys
from setuptools import setup, Extension

import pybind11

if sys.platform == 'win32':
    VCPKG_ROOT = os.environ.get("VCPKG_ROOT", ".")
    include_dirs = [os.path.join(VCPKG_ROOT, "installed", "x64-windows", "include")]
    library_dirs = [os.path.join(VCPKG_ROOT, "installed", "x64-windows", "lib")]
    libraries = ["jpeg", "libssl", "libcrypto"]
else:
    include_dirs = []
    library_dirs = []
    libraries = ["jpeg", "ssl", "crypto"]


f5_stego_module = Extension(
    name="Arcova.f5_stego",
    sources=[
        "Arcova/f5_steg/F5_stego_binding.cpp",
        "Arcova/f5_steg/F5steg.cpp"
    ],
    include_dirs=[
        pybind11.get_include(),
        *include_dirs
    ],
    library_dirs=library_dirs,
    libraries=libraries,
    language="c++"
)

setup(
    name="Arcova",
    version="1.0.0",
    author="walnutsec",
    packages=["Arcova", "Arcova.f5_steg"],
    ext_modules=[f5_stego_module],
    zip_safe=False,
    setup_requires=['pybind11>=2.6', 'setuptools>=42', 'wheel'],
)
