#include "blinding.hpp"

#include <pybind11/cast.h>

#include <session/blinding.hpp>

#include "common.hpp"

namespace session {

void pybind_blinding(py::module m) {
    using namespace py::literals;
    m.def("blind25_id",
          &blind25_id,
          "session_id"_a,
          "server_pk"_a,
          "Computed a blinded session id using 25xxx-style Community pubkey blinding.\n\n"
          "Takes the (unblinded) Session ID and server pubkey as hex strings; returns the blinded "
          "id as a hex string.  This blinded pubkey is an Ed25519 pubkey, prefixed with '25'.");

    m.def(
            "blind25_sign",
            [](py::bytes ed_sk_bytes, std::string_view server_pk, py::bytes message) {
                auto ed_sk = usv_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64);
                auto sig = blind25_sign(ed_sk, server_pk, usv_from_pybytes(message));
                return py::bytes{from_unsigned_sv(sig)};
            },
            "ed25519_seckey"_a,
            "server_pubkey"_a,
            "message"_a,

            "Signs a message that is verifiable using the blinded 25xxx pubkey version of the "
            "given Session ID.\n\n"
            "- ed25519_seckey is the sodium-style 64-byte Ed25519 secret key underlying the "
            "Session ID, or *just* the 32-byte seed (in which case the pubkey will be computed).\n"
            "- server_pubkey is the community server pubkey, in hex (64 characters) or bytes (32)\n"
            "- message is the message to sign, in bytes\n\n"
            "Returns the 64-byte signature as bytes\n\n"
            "Note that there is no associated `blind25_verify` function because the resulting "
            "signature is verifiable as a standard Ed25519 signature using the blinded pubkey.");
}

}  // namespace session
