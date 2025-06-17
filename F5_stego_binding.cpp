#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "F5steg.cpp"

namespace py = pybind11;

PYBIND11_MODULE(f5_stego, m) {
    py::class_<Logger>(m, "Logger")
        .def(py::init<const std::string&>())
        .def("log", &Logger::log);

    py::class_<JpegHandler>(m, "JpegHandler")
        .def(py::init<>())
        .def("load", &JpegHandler::load)
        .def("save", &JpegHandler::save)
        .def("get_srcinfo", &JpegHandler::get_srcinfo, py::return_value_policy::reference_internal);

    py::class_<F5Steganography>(m, "F5Steganography")
        .def(py::init<Logger&>())
        .def("embed_data", &F5Steganography::embed_data)
        .def("extract_data", &F5Steganography::extract_data)
        .def("collect_modifiable_coeffs", &F5Steganography::collect_modifiable_coeffs)
        .def_property_readonly("capacity_bits", &F5Steganography::get_capacity_bits);

    py::class_<Crypto>(m, "Crypto")
        .def_static("encrypt", &Crypto::encrypt)
        .def_static("decrypt", &Crypto::decrypt);
}