const module = (() => {
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
        sign: (payload, secret, options) => {
            const algorithm = (options || {})["algorithm"] || "HS256";
            const header = {
                "typ": "JWT",
                "alg": algorithm
            }

            const message = _encode_dict(header) + "." + _encode_dict(payload);
            const signature = hash.digest(algorithm, secret, message);

            if (signature) {
                return message + "." + _encode(signature);
            }
        },

        verify: (token, secret, options) => {
            const components = token.split('.');

            if (components.length === 3) {
                const header = _decode_dict(components[0]);
                const payload = _decode_dict(components[1]);
                const message = components[0] + "." + components[1];
                const algorithm = header["alg"] || "HS256";
                const signature = hash.digest(algorithm, secret, message);

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
