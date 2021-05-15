var module = (function() {
    const hash = include("./hash.js");

    function _encode_dict(value) {
        return _encode(JSON.stringify(value));
    }

    function _encode(value) {
        return encode("base64url", value).replace(/=/g, "");
    }
    
    function _decode_dict(value) {
        return JSON.parse(encode("string", _decode(value)));
    }

    function _decode(value) {
        return decode("base64url", value);
    }

    return {
        sign: function(payload, secret, options) {
            var algorithm = (options || {})["algorithm"] || "HS256";
            var header = {
                "typ": "JWT",
                "alg": algorithm
            }

            var message = _encode_dict(header) + "." + _encode_dict(payload);
            var signature = hash.digest(algorithm, secret, message);

            if (signature) {
                return message + "." + _encode(signature);
            }
        },

        verify: function(token, secret, options) {
            var components = token.split('.');

            if (components.length === 3) {
                var header = _decode_dict(components[0]);
                var payload = _decode_dict(components[1]);
                var message = components[0] + "." + components[1];
                var algorithm = header["alg"] || "HS256";
                var signature = hash.digest(algorithm, secret, message);

                if (signature && _encode(signature) === components[2]) {
                    if ((options || {})["complete"]) {
                        return {
                            "header": header,
                            "payload": payload
                        }
                    }
                    
                    return payload;
                }
            }
        },
    }
})();

__MODULE__ = module;
