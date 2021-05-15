var module = (function() {
    const crypto = require("crypto");

    function _hmac_digest(hash, secret, data) {
        var key = crypto.string_to_bits(secret);
        var bits = crypto.hmac.digest(hash, key, data);

        return crypto.bytes_from_bits(bits);
    }

    return {
        digest: function(algorithm, secret, data) {
            if (algorithm === 'HS256') {
                return _hmac_digest("sha256", secret, data);
            }
        }
    }
})();

__MODULE__ = module;
