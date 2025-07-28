# setup.py
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
    libraries=["jpeg"],
    language="c++"
)

setup(
    name="Arcova",
    version="1.0.0",
    author="walnutsec",
    packages=find_packages(),
    ext_modules=[f5_stego_module],
    zip_safe=False
)
