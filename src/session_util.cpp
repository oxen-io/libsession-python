#include "blinding.hpp"
#include "onionreq.hpp"
#include "xed25519.hpp"

using namespace session;

PYBIND11_MODULE(session_util, m) {
    xed25519::pybind(m.def_submodule("xed25519"));
    onionreq::pybind(m.def_submodule("onionreq"));
    pybind_blinding(m.def_submodule("blinding"));
}
