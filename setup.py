# setup.py (VERSI FINAL YANG PALING BENAR)
import os
from setuptools import setup, Extension

import pybind11

is_in_ci = os.environ.get("CI") == "true"
VCPKG_ROOT = os.environ.get("GITHUB_WORKSPACE", ".")

vcpkg_include_path = os.path.join(VCPKG_ROOT, "vcpkg", "installed", "x64-windows", "include") if is_in_ci else ""
vcpkg_library_path = os.path.join(VCPKG_ROOT, "vcpkg", "installed", "x64-windows", "lib") if is_in_ci else ""

f5_stego_module = Extension(
    name="Arcova.f5_stego",
    sources=[
        "Arcova/f5_steg/F5_stego_binding.cpp",
        "Arcova/f5_steg/F5steg.cpp"
    ],
    include_dirs=[
        pybind11.get_include(),
        vcpkg_include_path
    ],
    library_dirs=[
        vcpkg_library_path
    ],
    libraries=["jpeg", "libssl", "libcrypto"],
    language="c++"
)

setup(
    name="Arcova",
    version="1.0.0",
    author="walnutsec",
    packages=["Arcova", "Arcova.f5_steg"],
    ext_modules=[f5_stego_module],
    zip_safe=False,
    # Menambahkan dependensi build, bisa membantu
    setup_requires=['pybind11>=2.6', 'setuptools>=42', 'wheel'],
)
