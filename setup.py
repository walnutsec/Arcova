# setup.py (Versi Final dengan Alamat Absolut)

import sys
import os
from setuptools import setup, Extension, find_packages

# Blok ini untuk kompatibilitas g++ di Windows
if sys.platform == 'win32':
    import distutils.cygwinccompiler
    distutils.cygwinccompiler.get_msvcr = lambda: []

# --- INI BAGIAN YANG DIPERBAIKI ---
# Dapatkan path absolut ke folder utama proyek (tempat setup.py berada)
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

# Buat path absolut ke setiap file source C++
cpp_source_files = [
    os.path.join(PROJECT_ROOT, "src", "Arcova", "f5_stego", "F5_stego_binding.cpp"),
    os.path.join(PROJECT_ROOT, "src", "Arcova", "f5_stego", "F5steg.cpp")
]
# --- SELESAI PERBAIKAN ---

ext_modules = [
    Extension(
        name="Arcova.f5_stego",
        sources=cpp_source_files,
        include_dirs=[
            __import__('pybind11').get_include(),
            # Path ini mungkin perlu disesuaikan jika MSYS2 lu di tempat lain
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
    name="Arcova",
    version="1.0.0",
    author="N0cturn1s",
    description="Arcova Protocol for file encryption and steganography.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    ext_modules=ext_modules,
    zip_safe=False,
)