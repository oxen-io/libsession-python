#include "xed25519.hpp"

#include <session/types.hpp>
#include <session/xed25519.hpp>

namespace py = pybind11;
namespace session::xed25519 {

using namespace std::literals;
using namespace py::literals;

namespace {
    ustring_view uview(py::bytes& in, size_t required_size = 0, const char* arg_name = "argument") {
        char* ptr;
        ssize_t sz;
        PyBytes_AsStringAndSize(in.ptr(), &ptr, &sz);

        size_t size = static_cast<size_t>(sz);
        if (required_size && size != required_size)
            throw std::invalid_argument{
                    "Invalid "s + arg_name + " value: expected " + std::to_string(required_size) +
                    " bytes"};
        return ustring_view{reinterpret_cast<unsigned char*>(ptr), size};
    }
}  // namespace

void pybind(pybind11::module m) {
    using namespace pybind11::literals;

    m.def(
            "sign",
            [](py::bytes curve25519_privkey, py::bytes msg) {
                auto a = uview(curve25519_privkey, 32, "curve25519_privkey");
                auto sig = sign(a, uview(msg));
                return py::bytes(reinterpret_cast<const char*>(sig.data()), sig.size());
            },
            "curve25519_privkey"_a,
            "msg"_a,
            "Constructs an XEd25519 signature of `msg` using the given X25519 private key");

    m.def(
            "pubkey",
            [](py::bytes curve25519_pubkey) {
                auto A = uview(curve25519_pubkey, 32, "curve25519_pubkey");
                auto edpk = pubkey(A);
                return py::bytes(reinterpret_cast<const char*>(edpk.data()), edpk.size());
            },
            "curve25519_pubkey"_a,
            "Returns the derived Ed25519 pubkey from a X25519 pubkey.  There are two possible "
            "Ed25519 pubkeys that convert to any given X25519 pubkey (via sodium's Ed -> curve "
            "conversion functions), which differ in their sign bit: this function always returns "
            "the positive (i.e. with the 0x80 bit of the last byte unset), as required by the "
            "XEd25519 specification.  (You can obtain the alternative, i.e. the negative, by "
            "setting the 0x80 bit in the last byte of the returned pubkey.)");

    m.def(
            "verify",
            [](py::bytes signature, py::bytes curve25519_pubkey, py::bytes msg) {
                auto sig = uview(signature, 64, "signature");
                auto A = uview(curve25519_pubkey, 32, "curve25519_pubkey");
                return verify(sig, A, uview(msg));
            },
            "signature"_a,
            "curve25519_pubkey"_a,
            "msg"_a,
            "Verifies the XEd25519 signature `signature` of `msg` allegedly signed by "
            "`curve25519_pubkey`.");
}

}  // namespace session::xed25519
