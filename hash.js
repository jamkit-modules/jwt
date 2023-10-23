const module = (() => {
    const crypto = require("crypto");

    function _hmac_digest(hash, secret, data) {
        const key = crypto.string_to_bits(secret);
        const bits = crypto.hmac.digest(hash, key, data);

        return crypto.bytes_from_bits(bits);
    }

    return {
        digest: (algorithm, secret, data) => {
            if (algorithm === 'HS256') {
                return _hmac_digest("sha256", secret, data);
            }
        }
    }
})();

__MODULE__ = module;
