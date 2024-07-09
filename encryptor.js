const cryptoJS = require("crypto-js")
const crypto = require("crypto")
const bcryptjs = require("bcrypt")

const key = 'b3r4sput1h'
class Encryptor {
    constructor() {
        this.encryptascii = this.encryptascii.bind(this)
        this.decryptascii = this.decryptascii.bind(this)
    }

    HmacSHA1Encrypt(payload) {
        const encrypted = cryptoJS.HmacSHA1(payload, key).toString()
        return encrypted
    }

    HmacSHA256Encrypt(payload) {
        const encrypted = cryptoJS.HmacSHA256(payload, key).toString()
        return encrypted
    }

    encryptascii(str) {
        const dataKey = {};
        for (let i = 0; i < key.length; i++) {
            dataKey[i] = key.substr(i, 1);
        }

        let strEnc = "";
        let nkey = 0;
        const jml = str.length;

        for (let i = 0; i < parseInt(jml); i++) {
            strEnc =
                strEnc +
                this.hexEncode(str[i].charCodeAt(0) + dataKey[nkey].charCodeAt(0));

            if (nkey === Object.keys(dataKey).length - 1) {
                nkey = 0;
            }
            nkey = nkey + 1;
        }
        return strEnc.toUpperCase();
    }

    decryptascii(str) {
        if (str) {
            const dataKey = {};
            for (let i = 0; i < key.length; i++) {
                dataKey[i] = key.substr(i, 1);
            }

            let strDec = "";
            let nkey = 0;
            const jml = str.length;
            let i = 0;
            while (i < parseInt(jml)) {
                strDec =
                    strDec +
                    this.chr(this.hexdec(str.substr(i, 2)) - dataKey[nkey].charCodeAt(0));
                if (nkey === Object.keys(dataKey).length - 1) {
                    nkey = 0;
                }
                nkey = nkey + 1;
                i = i + 2;
            }
            return strDec;
        }
    }

    hexEncode(str) {
        let result = "";
        result = str.toString(16);
        return result;
    }

    hexdec(hex) {
        let str = "";
        str = parseInt(hex, 16);
        return str;
    }

    chr(asci) {
        let str = "";
        str = String.fromCharCode(asci);
        return str;
    }

    doEncrypt(dataBeforeCopy, ignore = [], encryptor = this.encryptascii) {
        
        if (!dataBeforeCopy) {
            return dataBeforeCopy;
        }
        if (
            typeof dataBeforeCopy === "object" &&
            !(dataBeforeCopy instanceof Date)
        ) {
            const data = Array.isArray(dataBeforeCopy)
                ? [...dataBeforeCopy]
                : { ...dataBeforeCopy };
            Object.keys(data).map((x) => {
                const result = ignore.find((find) => find === x);
                if (!result) {
                    if (Array.isArray(data[x])) {
                        data[x] = data[x].map((y, i) => {
                            if (typeof y === "string") {
                                return encryptor(y);
                            } else if (
                                typeof data[x] === "object" &&
                                data[x] &&
                                !(data[x] instanceof Date)
                            ) {
                                return this.doEncrypt(y, ignore, encryptor);
                            }
                            return false;
                        });
                    } else {
                        if (typeof data[x] === "string" && data[x]) {
                            data[x] = encryptor(data[x]);
                        } else if (typeof data[x] === "number" && data[x]) {
                            // Call Masking Number
                        } else if (
                            typeof data[x] === "object" &&
                            data[x] &&
                            !(dataBeforeCopy instanceof Date)
                        ) {
                            data[x] = this.doEncrypt(data[x], ignore, encryptor);
                        }
                    }
                }
                return false;
            });
            return data;
        } else if (typeof dataBeforeCopy === "string") {
            const data = encryptor(dataBeforeCopy);
            return data;
        }
    }

    doDecrypt(dataBeforeCopy, ignore = [], decryptor = this.decryptascii) {
        if (!dataBeforeCopy) {
            return dataBeforeCopy;
        }

        if (
            typeof dataBeforeCopy === "object" &&
            !(dataBeforeCopy instanceof Date)
        ) {
            const data = Array.isArray(dataBeforeCopy)
                ? [...dataBeforeCopy]
                : { ...dataBeforeCopy };
            Object.keys(data).map((x) => {
                const result = ignore.find((find) => find === x);
                if (!result) {
                    if (Array.isArray(data[x])) {
                        data[x] = data[x].map((y, i) => {
                            if (typeof y === "string") {
                                return decryptor(y);
                            } else if (
                                typeof data[x] === "object" &&
                                data[x] &&
                                !(data[x] instanceof Date)
                            ) {
                                return this.doDecrypt(y, ignore, decryptor);
                            }
                            return false;
                        });
                    } else {
                        // Real Encrypt
                        if (typeof data[x] === "string" && data[x]) {
                            data[x] = decryptor(data[x]);
                        } else if (typeof data[x] === "number" && data[x]) {
                            // Call Unmasking Number()
                        } else if (
                            typeof data[x] === "object" &&
                            data[x] &&
                            !(dataBeforeCopy instanceof Date)
                        ) {
                            data[x] = this.doDecrypt(data[x], ignore, decryptor);
                        }
                    }
                }
                return false;
            });
            return data;
        } else if (typeof dataBeforeCopy === "string") {
            const data = decryptor(dataBeforeCopy);
            return data;
        }
    }

    RC4Encrypt(originalPayload) {
        const ignore = []
        let payload = originalPayload
        if (Helper.isJSONString(payload)) {
            payload = JSON.parse(payload)
            if(typeof payload === "number") {
                payload = originalPayload
            }
            const objectValue = Array.isArray(payload) ? (payload[0] || {}) : payload

            for (const key of Object.keys(objectValue)) {
                const ignoreEl = document.getElementById('inline_select_' + key)
                if (ignoreEl.checked) {
                    ignore.push(key)
                }
            }
        }

        return this.doEncrypt(payload, ignore, (value) => {
            const chiper = crypto.createCipheriv('rc4', key, '')
            const chiperText = chiper.update(value, 'utf-8', 'hex')
            return chiperText.toUpperCase()
        })
    }

    RC4Decrypt(payload) {
        const ignore = []

        if (Helper.isJSONString(payload)) {
            payload = JSON.parse(payload)
            const objectValue = Array.isArray(payload) ? (payload[0] || {}) : payload

            for (const key of Object.keys(objectValue)) {
                const ignoreEl = document.getElementById('inline_select_' + key)
                if (ignoreEl.checked) {
                    ignore.push(key)
                }
            }
        }

        return this.doDecrypt(payload, ignore, (value) => {
            const chiper = crypto.createDecipheriv('rc4', key, '')
            return chiper.update(value, 'hex', 'utf-8')
        })
    }

    NagatechEncrypt(originalPayload) {
        const ignore = []
        let payload = originalPayload
        if (Helper.isJSONString(payload)) {
            payload = JSON.parse(payload)
            if(typeof payload === "number") {
                payload = originalPayload
            }
            const objectValue = Array.isArray(payload) ? (payload[0] || {}) : payload

            for (const key of Object.keys(objectValue)) {
                const ignoreEl = document.getElementById('inline_select_' + key)
                if (ignoreEl.checked) {
                    ignore.push(key)
                }
            }
        }

        return this.doEncrypt(payload, ignore)
    }

    NagatechDecrypt(payload) {
        const ignore = []

        if (Helper.isJSONString(payload)) {
            payload = JSON.parse(payload)
            const objectValue = Array.isArray(payload) ? (payload[0] || {}) : payload

            for (const key of Object.keys(objectValue)) {
                const ignoreEl = document.getElementById('inline_select_' + key)
                if (ignoreEl.checked) {
                    ignore.push(key)
                }
            }
        }

        return this.doDecrypt(payload, ignore)
    }

    async bcryptHash(payload) {
        const salt = await bcryptjs.genSalt(10)
        
        return await bcryptjs.hash(payload, salt)
    }

    async bcryptValidate(payload, payloadEncrypted) {
        return bcryptjs.compare(payload, payloadEncrypted)
    }
}

module.exports = Encryptor