# setup.py (VERSI FINAL Definitif)
from setuptools import setup, Extension, find_packages
import pybind11

f5_stego_module = Extension(
    name="Arcova.f5_stego",
    sources=[
        "Arcova/f5_steg/F5_stego_binding.cpp",
        "Arcova/f5_steg/F5steg.cpp"
    ],
    include_dirs=[
        pybind11.get_include()
    ],
    libraries=["jpeg", "ssl", "crypto"],
    language="c++"
)

setup(
    ext_modules=[f5_stego_module],
    packages=find_packages(),
    zip_safe=False
)
