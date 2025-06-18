# setup.py (Versi untuk LINUX)

from setuptools import setup, Extension, find_packages

# Path ke file-file C++ tetap sama relatif terhadap root
cpp_source_files = [
    "src/Arcova/f5_stego/F5_stego_binding.cpp",
    "src/Arcova/f5_stego/F5steg.cpp"
]

ext_modules = [
    Extension(
        name="Arcova.f5_stego",
        sources=cpp_source_files,
        include_dirs=[
            # Path header pybind11 otomatis
            __import__('pybind11').get_include(),
            # Di Linux, path lain tidak perlu karena compiler akan mencari di /usr/include
        ],
        # Library juga akan otomatis ditemukan di /usr/lib
        libraries=["jpeg", "ssl", "crypto"],
        extra_compile_args=["-std=c++17", "-Wall", "-O2", "-fPIC"],
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
