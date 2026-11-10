#include "swpor/error.h"

const char *swpor_strerror(int err)
{
    switch (err) {
    case SWPOR_OK:
        return "success";
    case SWPOR_E_INVALID_ARG:
        return "invalid argument";
    case SWPOR_E_NOMEM:
        return "out of memory";
    case SWPOR_E_IO:
        return "I/O error";
    case SWPOR_E_PARSE:
        return "malformed or non-canonical input";
    case SWPOR_E_TAG_AUTH:
        return "file tag authentication failed";
    case SWPOR_E_CRYPTO:
        return "cryptographic library error";
    case SWPOR_E_RANGE:
        return "value out of range";
    case SWPOR_E_UNSUPPORTED:
        return "unsupported version, scheme or parameter";
    case SWPOR_E_NET:
        return "network error";
    case SWPOR_E_TIMEOUT:
        return "timed out";
    case SWPOR_E_BUSY:
        return "server busy";
    case SWPOR_E_EXISTS:
        return "already exists";
    case SWPOR_E_NOT_FOUND:
        return "not found";
    case SWPOR_E_DECODE:
        return "erasure decoding failed";
    case SWPOR_E_NOT_IMPLEMENTED:
        return "not implemented yet";
    default:
        return "unknown error";
    }
}
