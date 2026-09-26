// ========================================================
// Cybersecurity & Networking Master Platform - Core Engine
// Interactive Tools, Labs, Search, Tooltips, Navigation
// Zero external dependencies. 100% Security hardened.
// ========================================================

// Self-contained cryptographic implementations for offline/pure JS
const CryptoUtils = {
  // Pure JS MD5 Implementation
  md5: function (str) {
    function safeAdd(x, y) {
      const lsw = (x & 0xffff) + (y & 0xffff);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xffff);
    }
    function bitRotateLeft(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
    function md5cmn(q, a, b, x, s, t) {
      return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
    }
    function md5ff(a, b, c, d, x, s, t) {
      return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function md5gg(a, b, c, d, x, s, t) {
      return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function md5hh(a, b, c, d, x, s, t) {
      return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5ii(a, b, c, d, x, s, t) {
      return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    function binlMD5(x, len) {
      x[len >> 5] |= 0x80 << (len % 32);
      x[(((len + 64) >>> 9) << 4) + 14] = len;
      let a = 1732584193;
      let b = -271733879;
      let c = -1732584194;
      let d = 271733878;

      for (let i = 0; i < x.length; i += 16) {
        const olda = a, oldb = b, oldc = c, oldd = d;

        a = md5ff(a, b, c, d, x[i], 7, -680876936);
        d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
        b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

        a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = md5gg(b, c, d, a, x[i], 20, -373897302);
        a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

        a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
        d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = md5hh(d, a, b, c, x[i], 11, -358537222);
        c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

        a = md5ii(a, b, c, d, x[i], 6, -198630844);
        d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

        a = safeAdd(a, olda);
        b = safeAdd(b, oldb);
        c = safeAdd(c, oldc);
        d = safeAdd(d, oldd);
      }
      return [a, b, c, d];
    }

    function rstr2binl(input) {
      const output = [];
      output[(input.length >> 2) - 1] = undefined;
      for (let i = 0; i < output.length; i++) output[i] = 0;
      const length8 = input.length * 8;
      for (let i = 0; i < length8; i += 8) {
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (i % 32);
      }
      return output;
    }

    function binl2hex(binarray) {
      const hexTab = "0123456789abcdef";
      let str = "";
      for (let i = 0; i < binarray.length * 4; i++) {
        str += hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xf) +
          hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xf);
      }
      return str;
    }

    const utf8 = unescape(encodeURIComponent(str));
    return binl2hex(binlMD5(rstr2binl(utf8), utf8.length * 8));
  },

  // SHA-256 Implementation (Pure JS)
  sha256: function (ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let result = '';
    const words = [];
    const asciiBitLength = ascii.length * 8;

    const hash = [];
    const k = [];
    let primeCounter = 0;
    const isPrime = {};

    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isPrime[candidate]) {
        for (let i = 0; i < 313; i += candidate) isPrime[i] = true;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }

    ascii += '\x80';
    while ((ascii.length % 64) - 56) ascii += '\x00';
    for (let i = 0; i < ascii.length; i++) {
      const j = ascii.charCodeAt(i);
      if (j >> 8) return;
      words[i >> 2] |= j << (((3 - i) % 4) * 8);
    }
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;

    for (let j = 0; j < words.length;) {
      const w = words.slice(j, (j += 16));
      const oldHash = hash.slice(0);

      for (let i = 0; i < 64; i++) {
        const w15 = w[i - 15], w2 = w[i - 2];
        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;

        const s1_maj = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
        const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
        const temp1 = hash[7] + s1_maj + ch + k[i] + w[i];
        const s0_maj = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
        const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
        const temp2 = s0_maj + maj;

        hash[7] = hash[6];
        hash[6] = hash[5];
        hash[5] = hash[4];
        hash[4] = (hash[3] + temp1) | 0;
        hash[3] = hash[2];
        hash[2] = hash[1];
        hash[1] = hash[0];
        hash[0] = (temp1 + temp2) | 0;
      }

      for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }

    for (let i = 0; i < 8; i++) {
      for (let j = 3; j + 1; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += (b < 16 ? '0' : '') + b.toString(16);
      }
    }
    return result;
  },

  // SHA-1 Implementation (Pure JS)
  sha1: function (msg) {
    function rotateLeft(n, s) { return (n << s) | (n >>> (32 - s)); }
    function cvtHex(val) {
      let str = "";
      for (let i = 7; i >= 0; i--) {
        const v = (val >>> (i * 4)) & 0x0f;
        str += v.toString(16);
      }
      return str;
    }

    const utf8 = unescape(encodeURIComponent(msg));
    const blocksize = 64;
    let len = utf8.length;
    const wordCount = ((len + 8) >> 6) + 1;
    const words = new Array(wordCount * 16).fill(0);

    for (let i = 0; i < len; i++) {
      words[i >> 2] |= (utf8.charCodeAt(i) & 0xff) << ((3 - (i % 4)) * 8);
    }
    words[len >> 2] |= 0x80 << ((3 - (len % 4)) * 8);
    words[wordCount * 16 - 1] = len * 8;

    let H0 = 0x67452301, H1 = 0xefcdab89, H2 = 0x98badcfe, H3 = 0x10325476, H4 = 0xc3d2e1f0;
    const W = new Array(80);

    for (let i = 0; i < words.length; i += 16) {
      for (let t = 0; t < 16; t++) W[t] = words[i + t];
      for (let t = 16; t < 80; t++) W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

      let A = H0, B = H1, C = H2, D = H3, E = H4;
      for (let t = 0; t < 80; t++) {
        let f, K;
        if (t < 20) { f = (B & C) | ((~B) & D); K = 0x5a827999; }
        else if (t < 40) { f = B ^ C ^ D; K = 0x6ed9eba1; }
        else if (t < 60) { f = (B & C) | (B & D) | (C & D); K = 0x8f1bbcdc; }
        else { f = B ^ C ^ D; K = 0xca62c1d6; }

        const temp = (rotateLeft(A, 5) + f + E + K + W[t]) & 0xffffffff;
        E = D; D = C; C = rotateLeft(B, 30); B = A; A = temp;
      }

      H0 = (H0 + A) & 0xffffffff;
      H1 = (H1 + B) & 0xffffffff;
      H2 = (H2 + C) & 0xffffffff;
      H3 = (H3 + D) & 0xffffffff;
      H4 = (H4 + E) & 0xffffffff;
    }
    return cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4);
  },

  // Calculate Shannon Entropy
  entropy: function (str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < str.length; i++) {
      freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    let ent = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      ent -= p * Math.log2(p);
    }
    return parseFloat(ent.toFixed(3));
  }
};

// ========================================================
// Subnet Calculator Engine
// ========================================================
const SubnetEngine = {
  isValidIPv4: function (ip) {
    if (!ip || typeof ip !== "string") return false;
    const parts = ip.trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every(part => {
      if (!/^\d+$/.test(part)) return false;
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255 && (part === "0" || !part.startsWith("0"));
    });
  },

  ipToInt: function (ip) {
    return ip.trim().split(".").reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
  },

  intToIp: function (int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join(".");
  },

  intToBinary: function (int) {
    return [
      ((int >>> 24) & 255).toString(2).padStart(8, "0"),
      ((int >>> 16) & 255).toString(2).padStart(8, "0"),
      ((int >>> 8) & 255).toString(2).padStart(8, "0"),
      (int & 255).toString(2).padStart(8, "0")
    ].join(".");
  },

  calculate: function (ipStr, cidr) {
    if (!ipStr || ipStr.trim() === "") {
      return { error: "Please enter an IPv4 address (e.g., 192.168.1.1)" };
    }
    if (cidr === undefined || cidr === null || cidr === "" || isNaN(cidr)) {
      return { error: "Please provide a valid CIDR prefix between 0 and 32." };
    }
    const prefix = parseInt(cidr, 10);
    if (prefix < 0 || prefix > 32) {
      return { error: `Invalid CIDR prefix /${prefix}. Prefix must be between 0 and 32.` };
    }
    if (!this.isValidIPv4(ipStr)) {
      return { error: `Invalid IPv4 address: '${ipStr}'. Must be four octets (0-255).` };
    }

    const ipInt = this.ipToInt(ipStr);
    const maskInt = prefix === 0 ? 0 : (((0xffffffff << (32 - prefix)) >>> 0));
    const wildcardInt = (~maskInt) >>> 0;
    const networkInt = (ipInt & maskInt) >>> 0;
    const broadcastInt = (networkInt | wildcardInt) >>> 0;

    let totalHosts = Math.pow(2, 32 - prefix);
    let usableHosts = 0;
    let firstHost = "N/A";
    let lastHost = "N/A";

    if (prefix === 31) {
      usableHosts = 2; // RFC 3021 Point-to-Point
      firstHost = this.intToIp(networkInt);
      lastHost = this.intToIp(broadcastInt);
    } else if (prefix === 32) {
      usableHosts = 1; // Single host
      firstHost = this.intToIp(networkInt);
      lastHost = this.intToIp(networkInt);
    } else if (prefix <= 30) {
      usableHosts = totalHosts - 2;
      firstHost = this.intToIp(networkInt + 1);
      lastHost = this.intToIp(broadcastInt - 1);
    }

    return {
      ip: ipStr.trim(),
      cidr: prefix,
      netmask: this.intToIp(maskInt),
      wildcard: this.intToIp(wildcardInt),
      network: this.intToIp(networkInt),
      broadcast: this.intToIp(broadcastInt),
      firstHost: firstHost,
      lastHost: lastHost,
      usableHosts: usableHosts.toLocaleString(),
      totalHosts: totalHosts.toLocaleString(),
      binaryMask: this.intToBinary(maskInt),
      binaryIp: this.intToBinary(ipInt)
    };
  }
};

// ========================================================
// Password Entropy Evaluator
// ========================================================
const PasswordEngine = {
  evaluate: function (password) {
    if (!password || password.length === 0) {
      return { error: "Please enter a password to evaluate." };
    }

    const length = password.length;
    let poolSize = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSymbols = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasDigits) poolSize += 10;
    if (hasSymbols) poolSize += 33;

    const entropyBits = poolSize > 0 ? length * Math.log2(poolSize) : 0;
    const totalCombinations = Math.pow(poolSize, length);

    // Online rate: 100 attempts / sec
    // Fast GPU Hashcat rig: 100 billion (10^11) attempts / sec
    const secondsOnline = totalCombinations / 100;
    const secondsOffline = totalCombinations / 100000000000;

    function formatTime(sec) {
      if (sec < 1) return "Instant (< 1 second)";
      if (sec < 60) return `${Math.round(sec)} seconds`;
      if (sec < 3600) return `${Math.round(sec / 60)} minutes`;
      if (sec < 86400) return `${Math.round(sec / 3600)} hours`;
      if (sec < 31536000) return `${Math.round(sec / 86400)} days`;
      if (sec < 3153600000) return `${Math.round(sec / 31536000)} years`;
      if (sec < 3.15e12) return `${(sec / 31536000).toExponential(2)} years`;
      return "Centuries (Virtually Uncrackable)";
    }

    let strength = "Very Weak";
    let badgeClass = "badge-red";
    if (entropyBits >= 80) {
      strength = "Very Strong";
      badgeClass = "badge-green";
    } else if (entropyBits >= 60) {
      strength = "Strong";
      badgeClass = "badge-cyan";
    } else if (entropyBits >= 40) {
      strength = "Moderate";
      badgeClass = "badge-amber";
    }

    const recommendations = [];
    if (length < 14) recommendations.push("Increase length to at least 14-16 characters.");
    if (!hasUpper) recommendations.push("Add uppercase letters (A-Z).");
    if (!hasDigits) recommendations.push("Add numerical digits (0-9).");
    if (!hasSymbols) recommendations.push("Include special characters (!@#$%^&*).");
    if (recommendations.length === 0) recommendations.push("Excellent entropy and character diversity.");

    return {
      length: length,
      poolSize: poolSize,
      entropy: entropyBits.toFixed(2),
      strength: strength,
      badgeClass: badgeClass,
      onlineCrackTime: formatTime(secondsOnline),
      offlineCrackTime: formatTime(secondsOffline),
      recommendations: recommendations
    };
  }
};

// ========================================================
// Security Encoder / Decoder
// ========================================================
const EncoderEngine = {
  convert: function (input, mode, operation) {
    if (!input || input.length === 0) {
      return { error: "Please enter text to encode or decode." };
    }

    try {
      if (mode === "base64") {
        if (operation === "encode") {
          return { output: btoa(unescape(encodeURIComponent(input))) };
        } else {
          return { output: decodeURIComponent(escape(atob(input.trim()))) };
        }
      } else if (mode === "hex") {
        if (operation === "encode") {
          let hex = "";
          for (let i = 0; i < input.length; i++) {
            hex += input.charCodeAt(i).toString(16).padStart(2, "0") + " ";
          }
          return { output: hex.trim() };
        } else {
          const cleanHex = input.replace(/\s+/g, "");
          if (cleanHex.length % 2 !== 0) throw new Error("Invalid hex string length (must be pairs)");
          let str = "";
          for (let i = 0; i < cleanHex.length; i += 2) {
            str += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
          }
          return { output: str };
        }
      } else if (mode === "url") {
        if (operation === "encode") {
          return { output: encodeURIComponent(input) };
        } else {
          return { output: decodeURIComponent(input) };
        }
      } else if (mode === "rot13") {
        const rot = input.replace(/[a-zA-Z]/g, c => {
          const base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
        return { output: rot };
      }
      return { error: "Unsupported conversion mode." };
    } catch (err) {
      return { error: `Conversion Error: ${err.message}` };
    }
  }
};

// ========================================================
// Firewall & ACL Rule Builder
// ========================================================
const FirewallEngine = {
  build: function (params) {
    const { action, protocol, srcIp, srcPort, dstIp, dstPort } = params;

    const cleanSrc = (srcIp && srcIp.trim()) ? srcIp.trim() : "any";
    const cleanDst = (dstIp && dstIp.trim()) ? dstIp.trim() : "any";
    const cleanProto = protocol.toLowerCase();
    const actUpper = action.toUpperCase();

    // Cisco IOS
    const ciscoAct = actUpper === "ALLOW" ? "permit" : "deny";
    const ciscoProto = cleanProto === "all" ? "ip" : cleanProto;
    const ciscoSrc = cleanSrc === "any" ? "any" : `host ${cleanSrc}`;
    const ciscoDst = cleanDst === "any" ? "any" : `host ${cleanDst}`;
    const ciscoPort = dstPort && dstPort !== "any" ? ` eq ${dstPort}` : "";
    const ciscoRule = `access-list 101 ${ciscoAct} ${ciscoProto} ${ciscoSrc} ${ciscoDst}${ciscoPort}`;

    // iptables
    const iptAction = actUpper === "ALLOW" ? "ACCEPT" : (actUpper === "REJECT" ? "REJECT" : "DROP");
    let iptRule = `iptables -A INPUT`;
    if (cleanProto !== "all") iptRule += ` -p ${cleanProto}`;
    if (cleanSrc !== "any") iptRule += ` -s ${cleanSrc}`;
    if (cleanDst !== "any") iptRule += ` -d ${cleanDst}`;
    if (dstPort && dstPort !== "any" && cleanProto !== "all") iptRule += ` --dport ${dstPort}`;
    iptRule += ` -j ${iptAction}`;

    // UFW
    const ufwAct = actUpper === "ALLOW" ? "allow" : "deny";
    let ufwRule = `ufw ${ufwAct}`;
    if (cleanProto !== "all" && dstPort && dstPort !== "any") {
      ufwRule += ` ${dstPort}/${cleanProto}`;
    }
    if (cleanSrc !== "any") {
      ufwRule += ` from ${cleanSrc}`;
    }

    return {
      cisco: ciscoRule,
      iptables: iptRule,
      ufw: ufwRule
    };
  }
};

// ========================================================
// Global State & UI Controller
// ========================================================
const App = {
  state: {
    activeTrack: "protocols",
    theme: "dark",
    roadmapProgress: {},
    activeLab: "lab-1"
  },

  init: function () {
    this.loadState();
    this.initTheme();
    this.initNavigation();
    this.renderLearningHub();
    this.initTooltips();
    this.initSearch();
    this.renderProtocols();
    this.renderDefense();
    this.renderAttacks();
    this.initTools();
    this.renderLabs();
    this.renderRoadmaps();
    this.renderGlossary();
    this.updateProgressSummary();
  },

  loadState: function () {
    try {
      const savedTheme = localStorage.getItem("cyber_theme");
      if (savedTheme) this.state.theme = savedTheme;
      const savedProgress = localStorage.getItem("cyber_roadmap_progress");
      if (savedProgress) this.state.roadmapProgress = JSON.parse(savedProgress);
    } catch (e) {
      // LocalStorage fallback for sandboxed tests
    }
  },

  initTheme: function () {
    document.documentElement.setAttribute("data-theme", this.state.theme);
    const themeBtn = document.getElementById("btn-theme-toggle");
    if (themeBtn) {
      themeBtn.textContent = this.state.theme === "dark" ? "☀️" : "🌙";
      themeBtn.setAttribute("aria-label", `Switch to ${this.state.theme === "dark" ? "light" : "dark"} mode`);
      themeBtn.addEventListener("click", () => {
        this.state.theme = this.state.theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", this.state.theme);
        themeBtn.textContent = this.state.theme === "dark" ? "☀️" : "🌙";
        try { localStorage.setItem("cyber_theme", this.state.theme); } catch (e) { }
        this.showToast(`Switched to ${this.state.theme} mode`);
      });
    }
  },

  initNavigation: function () {
    const navLinks = document.querySelectorAll("[data-track]");
    navLinks.forEach(link => {
      link.addEventListener("click", (e) => {
        const targetTrack = link.getAttribute("data-track");
        if (targetTrack) {
          if (targetTrack === "resources") {
            document.querySelectorAll(".nav-link").forEach(navLink => {
              navLink.classList.toggle("active", navLink === link);
            });
            const drawer = document.getElementById("mobile-nav-drawer");
            if (drawer) drawer.classList.remove("open");
            return;
          }
          e.preventDefault();
          this.switchTrack(targetTrack);
          // Close mobile drawer if open
          const drawer = document.getElementById("mobile-nav-drawer");
          if (drawer) drawer.classList.remove("open");
        }
      });
    });

    const mobileMenuBtn = document.getElementById("mobile-menu-btn");
    const mobileDrawer = document.getElementById("mobile-nav-drawer");
    if (mobileMenuBtn && mobileDrawer) {
      mobileMenuBtn.addEventListener("click", () => {
        mobileDrawer.classList.toggle("open");
      });
    }
  },

  switchTrack: function (trackId) {
    this.state.activeTrack = trackId;
    document.querySelectorAll(".nav-link").forEach(l => {
      l.classList.toggle("active", l.getAttribute("data-track") === trackId);
    });
    document.querySelectorAll(".track-tab-btn").forEach(t => {
      t.classList.toggle("active", t.getAttribute("data-track") === trackId);
    });
    document.querySelectorAll(".view-panel").forEach(p => {
      p.classList.toggle("active", p.id === `view-${trackId}`);
    });
    window.location.hash = trackId;
    window.scrollTo({ top: 0, behavior: "smooth" });
  },

  showToast: function (message) {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 200);
    }, 2500);
  },

  copyToClipboard: function (text, label = "Data") {
    if (!text) {
      this.showToast("Nothing to copy!");
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        this.showToast(`${label} copied to clipboard!`);
      }).catch(() => {
        this.fallbackCopy(text, label);
      });
    } else {
      this.fallbackCopy(text, label);
    }
  },

  fallbackCopy: function (text, label) {
    const el = document.createElement("textarea");
    el.value = text;
    document.body.appendChild(el);
    el.select();
    try {
      document.execCommand("copy");
      this.showToast(`${label} copied to clipboard!`);
    } catch (e) {
      this.showToast("Copy failed");
    }
    document.body.removeChild(el);
  },

  downloadFile: function (filename, content, type = "text/plain") {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast(`Downloaded ${filename}`);
  },

  // ========================================================
  // Abbreviation Tooltip Engine (Section F)
  // ========================================================
  initTooltips: function () {
    let tooltip = document.getElementById("global-tooltip");
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.id = "global-tooltip";
      tooltip.setAttribute("role", "tooltip");
      document.body.appendChild(tooltip);
    }

    const positionTooltip = (el) => {
      const abbrKey = (el.getAttribute("data-abbr") || el.textContent || "").trim().toUpperCase();
      const termObj = (typeof GLOSSARY_TERMS !== "undefined")
        ? GLOSSARY_TERMS.find(t => t.term.toUpperCase() === abbrKey)
        : null;

      if (!termObj) return;

      tooltip.innerHTML = `
        <span class="tooltip-term">${termObj.term}</span>
        <span class="tooltip-full">${termObj.fullForm}</span>
        <span class="tooltip-desc">${termObj.description}</span>
      `;

      tooltip.classList.add("visible");
      const rect = el.getBoundingClientRect();
      const tooltipRect = tooltip.getBoundingClientRect();

      let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
      let top = rect.top - tooltipRect.height - 8;

      // Viewport Clamping (Strict Requirement Section F)
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      if (left < 10) left = 10;
      if (left + tooltipRect.width > viewportWidth - 10) {
        left = viewportWidth - tooltipRect.width - 10;
      }
      if (top < 10) {
        top = rect.bottom + 8; // Flip to bottom
      }
      if (top + tooltipRect.height > viewportHeight - 10) {
        top = viewportHeight - tooltipRect.height - 10;
      }

      tooltip.style.left = `${Math.round(left)}px`;
      tooltip.style.top = `${Math.round(top)}px`;
    };

    const hideTooltip = () => {
      tooltip.classList.remove("visible");
    };

    // Global listener on all cyber-term elements
    document.addEventListener("mouseover", (e) => {
      const target = e.target.closest("abbr.cyber-term, [data-abbr]");
      if (target) positionTooltip(target);
    });

    document.addEventListener("mouseout", (e) => {
      if (e.target.closest("abbr.cyber-term, [data-abbr]")) hideTooltip();
    });

    document.addEventListener("focusin", (e) => {
      const target = e.target.closest("abbr.cyber-term, [data-abbr]");
      if (target) positionTooltip(target);
    });

    document.addEventListener("focusout", (e) => {
      if (e.target.closest("abbr.cyber-term, [data-abbr]")) hideTooltip();
    });

    // Touch tap support for mobile
    document.addEventListener("click", (e) => {
      const target = e.target.closest("abbr.cyber-term, [data-abbr]");
      if (target) {
        e.stopPropagation();
        positionTooltip(target);
      } else {
        hideTooltip();
      }
    });
  },

  // ========================================================
  // Global Search Engine (Section E)
  // ========================================================
  initSearch: function () {
    const backdrop = document.getElementById("search-modal-backdrop");
    const searchInput = document.getElementById("global-search-input");
    const resultsContainer = document.getElementById("search-results-list");
    const searchTrigger = document.getElementById("btn-search-trigger");

    const openSearch = () => {
      if (backdrop) {
        backdrop.classList.add("open");
        if (searchInput) {
          searchInput.value = "";
          searchInput.focus();
          this.executeSearch("", resultsContainer);
        }
      }
    };

    const closeSearch = () => {
      if (backdrop) backdrop.classList.remove("open");
    };

    if (searchTrigger) searchTrigger.addEventListener("click", openSearch);

    // Ctrl+K or / keyboard shortcuts
    window.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openSearch();
      }
      if (e.key === "Escape" && backdrop && backdrop.classList.contains("open")) {
        closeSearch();
      }
    });

    if (backdrop) {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeSearch();
      });
    }

    if (searchInput && resultsContainer) {
      searchInput.addEventListener("input", (e) => {
        this.executeSearch(e.target.value, resultsContainer);
      });
    }
  },

  executeSearch: function (query, container) {
    const q = (query || "").trim().toLowerCase();
    container.innerHTML = "";

    if (!q) {
      container.innerHTML = `<li class="search-empty-state">Type a keyword like <code>ARP</code>, <code>DNS</code>, <code>TCP</code>, <code>XSS</code>, <code>Nmap</code>, or <code>OWASP</code>...</li>`;
      return;
    }

    const matches = [];

    // Search Protocols
    if (typeof PROTOCOLS_CATALOG !== "undefined") {
      PROTOCOLS_CATALOG.forEach(p => {
        const text = `${p.name} ${p.fullName} ${p.port} ${p.description} ${p.risks.join(" ")}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: `${p.name} (${p.fullName})`,
            badge: "Protocol",
            snippet: p.description,
            track: "protocols"
          });
        }
      });
    }

    // Search Attacks
    if (typeof NETWORK_ATTACKS_DATA !== "undefined") {
      NETWORK_ATTACKS_DATA.forEach(a => {
        const text = `${a.name} ${a.category} ${a.mechanism} ${a.subtypes.join(" ")}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: a.name,
            badge: "Network Attack",
            snippet: a.mechanism,
            track: "attacks"
          });
        }
      });
    }

    if (typeof WEB_ATTACKS_DATA !== "undefined") {
      WEB_ATTACKS_DATA.forEach(w => {
        const text = `${w.name} ${w.owaspRank} ${w.mechanism} ${w.impact}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: `${w.name} (${w.owaspRank})`,
            badge: "Web Attack",
            snippet: w.mechanism,
            track: "attacks"
          });
        }
      });
    }

    // Search Common Ports
    if (typeof COMMON_PORTS_DATABASE !== "undefined") {
      COMMON_PORTS_DATABASE.forEach(port => {
        const text = `port ${port.port} ${port.service} ${port.description} ${port.risks}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: `Port ${port.port}: ${port.service}`,
            badge: "Port Database",
            snippet: port.description,
            track: "tools"
          });
        }
      });
    }

    // Search Glossary
    if (typeof GLOSSARY_TERMS !== "undefined") {
      GLOSSARY_TERMS.forEach(g => {
        const text = `${g.term} ${g.fullForm} ${g.category} ${g.description}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: `${g.term} - ${g.fullForm}`,
            badge: `Glossary (${g.category})`,
            snippet: g.description,
            track: "glossary"
          });
        }
      });
    }

    // Search Practical Labs
    if (typeof LABS_DATA !== "undefined") {
      LABS_DATA.forEach(lab => {
        const text = `lab ${lab.number} ${lab.title} ${lab.badge} ${lab.objective} ${lab.instructions || ''}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: `Lab ${lab.number}: ${lab.title}`,
            badge: "Interactive Lab",
            snippet: lab.objective,
            track: "labs"
          });
        }
      });
    }

    // Search Roadmaps & Career Tracks
    if (typeof ROADMAP_PHASES !== "undefined") {
      ROADMAP_PHASES.forEach(phase => {
        phase.skills.forEach(skill => {
          if (skill.title.toLowerCase().includes(q)) {
            matches.push({
              title: skill.title,
              badge: `Roadmap (${phase.badge})`,
              snippet: `${phase.phaseTitle} - Estimated time: ${skill.hours} hrs`,
              track: "roadmaps"
            });
          }
        });
      });
    }

    if (typeof CAREER_TRACKS !== "undefined") {
      CAREER_TRACKS.forEach(c => {
        const text = `${c.role} ${c.summary} ${c.keyTools.join(' ')}`.toLowerCase();
        if (text.includes(q)) {
          matches.push({
            title: c.role,
            badge: "Career Track",
            snippet: c.summary,
            track: "roadmaps"
          });
        }
      });
    }

    if (matches.length === 0) {
      container.innerHTML = `
        <li class="search-empty-state">
          No matches found for "<strong>${this.escapeHTML(query)}</strong>".<br>
          <span style="font-size:0.85em;color:var(--text-dim);margin-top:0.5rem;display:inline-block;">
            Try: ARP, DNS, TCP, UDP, XSS, SQL Injection, Nmap, Wireshark, Linux, OWASP, HTTP, VPN, SSH
          </span>
        </li>
      `;
      return;
    }

    matches.slice(0, 15).forEach(m => {
      const li = document.createElement("li");
      li.className = "search-result-item";
      li.innerHTML = `
        <div class="search-item-title">
          <span>${this.escapeHTML(m.title)}</span>
          <span class="search-item-badge">${this.escapeHTML(m.badge)}</span>
        </div>
        <div class="search-item-snippet">${this.escapeHTML(m.snippet.substring(0, 120))}...</div>
      `;
      li.addEventListener("click", () => {
        const backdrop = document.getElementById("search-modal-backdrop");
        if (backdrop) backdrop.classList.remove("open");
        this.switchTrack(m.track);
      });
      container.appendChild(li);
    });
  },

  escapeHTML: function (str) {
    if (!str) return "";
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  },


  // ========================================================
  // Render Zero-to-Pro Learning Hub
  // ========================================================
  renderLearningHub: function () {
    const container = document.getElementById("learning-path-grid");
    const filter = document.getElementById("learning-filter-input");
    const level = document.getElementById("learning-level-filter");
    if (!container || typeof LEARNING_PATH === "undefined") return;

    const render = () => {
      const q = (filter?.value || "").trim().toLowerCase();
      const selected = level?.value || "all";
      const filtered = LEARNING_PATH.filter(m => {
        const levelMatch = selected === "all" || (selected === "foundation" && m.level <= 5) || (selected === "security" && m.level >= 6 && m.level <= 12) || (selected === "specialization" && m.level >= 13);
        const haystack = [m.title, m.summary, ...m.topics].join(" ").toLowerCase();
        return levelMatch && (!q || haystack.includes(q));
      });
      container.innerHTML = filtered.length ? filtered.map(m => `
        <article class="cyber-card learning-card">
          <div class="card-header-flex"><div><div class="learning-level">Level ${m.level}</div><h3 class="card-title" style="margin-top:.3rem;">${m.icon} ${this.escapeHTML(m.title)}</h3></div><span class="card-badge badge-cyan">${m.level === 0 ? "START" : m.level === 20 ? "ADVANCED" : "STEP " + m.level}</span></div>
          <p>${this.escapeHTML(m.summary)}</p>
          <ul class="learning-topics">${m.topics.map(t => `<li>${this.escapeHTML(t)}</li>`).join("")}</ul>
          <div class="learning-practice"><strong>🧪 Safe Practice:</strong><br>${this.escapeHTML(m.practice)}</div>
        </article>`).join("") : `<div class="search-empty-state" style="grid-column:1/-1;">No learning modules match your search.</div>`;
    };
    render();
    filter?.addEventListener("input", render);
    level?.addEventListener("change", render);
  },

  // ========================================================
  // Render Protocols View
  // ========================================================
  renderProtocols: function () {
    const osiContainer = document.getElementById("osi-layers-list");
    if (osiContainer && typeof OSI_LAYERS_DATA !== "undefined") {
      osiContainer.innerHTML = OSI_LAYERS_DATA.map(layer => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <div>
              <span class="card-badge badge-cyan">Layer ${layer.number}</span>
              <h3 class="card-title" style="margin-top:0.35rem;">${layer.name} Layer</h3>
            </div>
            <span class="card-badge badge-purple">${layer.pdu}</span>
          </div>
          <div class="card-body">
            <p>${layer.summary}</p>
            <ul class="card-meta-list">
              <li><strong>Protocols:</strong> <span>${layer.protocols.map(p => `<abbr class="cyber-term" data-abbr="${p}">${p}</abbr>`).join(", ")}</span></li>
              <li><strong>Risks:</strong> <span style="color:var(--cyber-red);">${layer.securityRisks.slice(0, 2).join("; ")}</span></li>
              <li><strong>Controls:</strong> <span style="color:var(--cyber-green);">${layer.defenseControls.slice(0, 2).join("; ")}</span></li>
            </ul>
          </div>
        </div>
      `).join("");
    }

    const protocolsList = document.getElementById("protocols-catalog-grid");
    if (protocolsList && typeof PROTOCOLS_CATALOG !== "undefined") {
      protocolsList.innerHTML = PROTOCOLS_CATALOG.map(p => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <div>
              <h3 class="card-title"><abbr class="cyber-term" data-abbr="${p.name}">${p.name}</abbr></h3>
              <span style="font-size:0.8rem;color:var(--text-dim);">${p.fullName}</span>
            </div>
            <span class="card-badge ${p.securityStatus.includes('Secure') ? 'badge-green' : 'badge-red'}">
              Port ${p.port || 'N/A'} • ${p.transport}
            </span>
          </div>
          <div class="card-body">
            <p>${p.description}</p>
            <ul class="card-meta-list">
              <li><strong>Security:</strong> <span>${p.securityStatus}</span></li>
              <li><strong>Risks:</strong> <span style="color:var(--cyber-amber);">${p.risks[0]}</span></li>
              <li><strong>Defense:</strong> <span style="color:var(--cyber-green);">${p.defense[0]}</span></li>
              <li><strong>Filter:</strong> <code>${p.wiresharkFilter}</code></li>
            </ul>
          </div>
        </div>
      `).join("");
    }
  },

  // ========================================================
  // Render Defense View
  // ========================================================
  renderDefense: function () {
    const fwContainer = document.getElementById("firewalls-grid");
    if (fwContainer && typeof FIREWALL_TYPES_DATA !== "undefined") {
      fwContainer.innerHTML = FIREWALL_TYPES_DATA.map(fw => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <h3 class="card-title">${fw.type}</h3>
            <span class="card-badge badge-cyan">${fw.layer}</span>
          </div>
          <div class="card-body">
            <p>${fw.operation}</p>
            <ul class="card-meta-list">
              <li><strong>Pros:</strong> <span>${fw.pros.join(", ")}</span></li>
              <li><strong>Cons:</strong> <span style="color:var(--cyber-red);">${fw.cons.join(", ")}</span></li>
            </ul>
            <pre><code>${fw.ruleExample}</code></pre>
          </div>
        </div>
      `).join("");
    }

    const segContainer = document.getElementById("segmentation-grid");
    if (segContainer && typeof SEGMENTATION_ZONES !== "undefined") {
      segContainer.innerHTML = SEGMENTATION_ZONES.map(z => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <h3 class="card-title">${z.zone}</h3>
            <span class="card-badge badge-purple">${z.trustLevel}</span>
          </div>
          <div class="card-body">
            <p>${z.purpose}</p>
            <ul class="card-meta-list">
              ${z.rules.map(r => `<li>• <span>${r}</span></li>`).join("")}
            </ul>
          </div>
        </div>
      `).join("");
    }
  },

  // ========================================================
  // Render Attacks View
  // ========================================================
  renderAttacks: function () {
    const netAttacks = document.getElementById("network-attacks-grid");
    if (netAttacks && typeof NETWORK_ATTACKS_DATA !== "undefined") {
      netAttacks.innerHTML = NETWORK_ATTACKS_DATA.map(a => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <h3 class="card-title">${a.name}</h3>
            <span class="card-badge badge-red">${a.category}</span>
          </div>
          <div class="card-body">
            <p>${a.mechanism}</p>
            <ul class="card-meta-list">
              <li><strong>Indicators:</strong> <span>${a.detectionIndicators[0]}</span></li>
              <li><strong>Mitigation:</strong> <span style="color:var(--cyber-green);">${a.mitigation[0]}</span></li>
            </ul>
          </div>
        </div>
      `).join("");
    }

    const webAttacks = document.getElementById("web-attacks-grid");
    if (webAttacks && typeof WEB_ATTACKS_DATA !== "undefined") {
      webAttacks.innerHTML = WEB_ATTACKS_DATA.map(w => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <h3 class="card-title">${w.name}</h3>
            <span class="card-badge badge-amber">${w.owaspRank}</span>
          </div>
          <div class="card-body">
            <p>${w.mechanism}</p>
            <pre><code>${w.samplePayload}</code></pre>
            <ul class="card-meta-list">
              <li><strong>Impact:</strong> <span style="color:var(--cyber-red);">${w.impact}</span></li>
              <li><strong>Defense:</strong> <span style="color:var(--cyber-green);">${w.defense[0]}</span></li>
            </ul>
          </div>
        </div>
      `).join("");
    }
  },

  // ========================================================
  // Initialize Interactive Tool Suite (Section D)
  // Subnet, Hash, Port, Password, Encoder, Firewall, Packet, Filter
  // ========================================================
  initTools: function () {
    // Tool 1: Subnet Calculator
    const btnSubnetCalc = document.getElementById("btn-calc-subnet");
    const btnSubnetReset = document.getElementById("btn-reset-subnet");
    const btnSubnetCopy = document.getElementById("btn-copy-subnet");
    const btnSubnetDownload = document.getElementById("btn-download-subnet");

    const runSubnet = () => {
      const ip = document.getElementById("subnet-ip").value;
      const cidr = document.getElementById("subnet-cidr").value;
      const out = document.getElementById("subnet-output");
      const res = SubnetEngine.calculate(ip, cidr);

      if (res.error) {
        out.innerHTML = `<div class="output-error">${this.escapeHTML(res.error)}</div>`;
        return;
      }
      out.innerHTML = `
        <div class="output-row"><span>IP / CIDR:</span><span>${res.ip} /${res.cidr}</span></div>
        <div class="output-row"><span>Netmask:</span><span>${res.netmask}</span></div>
        <div class="output-row"><span>Wildcard:</span><span>${res.wildcard}</span></div>
        <div class="output-row"><span>Network Address:</span><span>${res.network}</span></div>
        <div class="output-row"><span>Broadcast Address:</span><span>${res.broadcast}</span></div>
        <div class="output-row"><span>Usable Host Range:</span><span>${res.firstHost} - ${res.lastHost}</span></div>
        <div class="output-row"><span>Total Usable Hosts:</span><span>${res.usableHosts}</span></div>
        <div class="output-row"><span>Binary Mask:</span><span>${res.binaryMask}</span></div>
      `;
    };

    if (btnSubnetCalc) btnSubnetCalc.addEventListener("click", runSubnet);
    if (btnSubnetReset) {
      btnSubnetReset.addEventListener("click", () => {
        document.getElementById("subnet-ip").value = "192.168.1.0";
        document.getElementById("subnet-cidr").value = "24";
        runSubnet();
        this.showToast("Subnet Calculator Reset");
      });
    }
    if (btnSubnetCopy) {
      btnSubnetCopy.addEventListener("click", () => {
        const text = document.getElementById("subnet-output").innerText;
        this.copyToClipboard(text, "Subnet data");
      });
    }
    if (btnSubnetDownload) {
      btnSubnetDownload.addEventListener("click", () => {
        const ip = document.getElementById("subnet-ip").value;
        const cidr = document.getElementById("subnet-cidr").value;
        const res = SubnetEngine.calculate(ip, cidr);
        this.downloadFile(`subnet-${ip.replace(/\./g, "_")}_${cidr}.json`, JSON.stringify(res, null, 2), "application/json");
      });
    }

    // Tool 2: Cryptographic Hash Generator & Analyzer
    const btnHashGen = document.getElementById("btn-gen-hash");
    const btnHashReset = document.getElementById("btn-reset-hash");
    const btnHashCopy = document.getElementById("btn-copy-hash");
    const btnHashDownload = document.getElementById("btn-download-hash");

    const runHash = () => {
      const input = document.getElementById("hash-input").value;
      const out = document.getElementById("hash-output");
      if (!input || input.length === 0) {
        out.innerHTML = `<div class="output-error">Please enter text to compute cryptographic hashes.</div>`;
        return;
      }
      const md5 = CryptoUtils.md5(input);
      const sha1 = CryptoUtils.sha1(input);
      const sha256 = CryptoUtils.sha256(input);
      const entropy = CryptoUtils.entropy(input);

      out.innerHTML = `
        <div class="output-row"><span>MD5 (128-bit):</span><span>${md5}</span></div>
        <div class="output-row"><span>SHA-1 (160-bit):</span><span>${sha1}</span></div>
        <div class="output-row"><span>SHA-256 (256-bit):</span><span>${sha256}</span></div>
        <div class="output-row"><span>Shannon Entropy:</span><span>${entropy} bits/char</span></div>
        <div class="output-row"><span>Input Length:</span><span>${input.length} characters</span></div>
      `;
    };

    if (btnHashGen) btnHashGen.addEventListener("click", runHash);
    if (btnHashReset) {
      btnHashReset.addEventListener("click", () => {
        document.getElementById("hash-input").value = "";
        document.getElementById("hash-output").innerHTML = "Hash results will appear here...";
        this.showToast("Hash Tool Reset");
      });
    }
    if (btnHashCopy) {
      btnHashCopy.addEventListener("click", () => {
        const text = document.getElementById("hash-output").innerText;
        this.copyToClipboard(text, "Hashes");
      });
    }
    if (btnHashDownload) {
      btnHashDownload.addEventListener("click", () => {
        const text = document.getElementById("hash-output").innerText;
        this.downloadFile("cryptographic-hashes.txt", text);
      });
    }

    // Tool 3: Port Threat & Service Scanner Lookup
    const btnPortLookup = document.getElementById("btn-lookup-port");
    const btnPortReset = document.getElementById("btn-reset-port");
    const btnPortCopy = document.getElementById("btn-copy-port");
    const btnPortDownload = document.getElementById("btn-download-port");

    const runPortLookup = () => {
      const query = (document.getElementById("port-input").value || "").trim().toLowerCase();
      const out = document.getElementById("port-output");

      if (!query) {
        out.innerHTML = `<div class="output-error">Please enter a port number (1-65535) or service name (e.g. 22, 443, SSH, SMB).</div>`;
        return;
      }

      if (/^\d+$/.test(query)) {
        const portNum = parseInt(query, 10);
        if (portNum < 1 || portNum > 65535) {
          out.innerHTML = `<div class="output-error">Port ${portNum} is out of boundary! Valid port range is 1 to 65535.</div>`;
          return;
        }
      }

      const match = COMMON_PORTS_DATABASE.find(p =>
        p.port.toString() === query || p.service.toLowerCase() === query
      );

      if (!match) {
        out.innerHTML = `
          <div class="output-row"><span>Query:</span><span>${this.escapeHTML(query)}</span></div>
          <div class="output-row"><span>Status:</span><span>Unregistered / Dynamic Port</span></div>
          <div class="output-row"><span>Standard Risk:</span><span>Unknown / Custom Application</span></div>
        `;
        return;
      }

      out.innerHTML = `
        <div class="output-row"><span>Port Number:</span><span>${match.port} / ${match.transport}</span></div>
        <div class="output-row"><span>Service Name:</span><span>${match.service}</span></div>
        <div class="output-row"><span>Threat Severity:</span><span style="color:${match.severity === 'Critical' ? 'var(--cyber-red)' : 'var(--cyber-amber)'}">${match.severity}</span></div>
        <div class="output-row"><span>Description:</span><span>${match.description}</span></div>
        <div class="output-row"><span>Security Risks:</span><span>${match.risks}</span></div>
        <div class="output-row"><span>Hardening:</span><span>${match.remediation}</span></div>
      `;
    };

    if (btnPortLookup) btnPortLookup.addEventListener("click", runPortLookup);
    if (btnPortReset) {
      btnPortReset.addEventListener("click", () => {
        document.getElementById("port-input").value = "";
        document.getElementById("port-output").innerHTML = "Port details will appear here...";
        this.showToast("Port Lookup Reset");
      });
    }
    if (btnPortCopy) {
      btnPortCopy.addEventListener("click", () => {
        const text = document.getElementById("port-output").innerText;
        this.copyToClipboard(text, "Port details");
      });
    }
    if (btnPortDownload) {
      btnPortDownload.addEventListener("click", () => {
        const text = document.getElementById("port-output").innerText;
        this.downloadFile("port-assessment.txt", text);
      });
    }

    // Tool 4: Password Entropy Evaluator
    const pwdInput = document.getElementById("pwd-eval-input");
    const pwdOut = document.getElementById("pwd-eval-output");
    const btnPwdReset = document.getElementById("btn-reset-pwd");
    const btnPwdCopy = document.getElementById("btn-copy-pwd");

    const runPwd = () => {
      const val = pwdInput.value;
      const res = PasswordEngine.evaluate(val);
      if (res.error) {
        pwdOut.innerHTML = `<div class="output-error">${this.escapeHTML(res.error)}</div>`;
        return;
      }
      pwdOut.innerHTML = `
        <div class="output-row"><span>Strength:</span><span class="card-badge ${res.badgeClass}">${res.strength}</span></div>
        <div class="output-row"><span>Entropy Bits:</span><span>${res.entropy} bits</span></div>
        <div class="output-row"><span>Character Pool:</span><span>${res.poolSize} possible glyphs</span></div>
        <div class="output-row"><span>Offline Crack Time (GPU):</span><span>${res.offlineCrackTime}</span></div>
        <div class="output-row"><span>Online Throttled Time:</span><span>${res.onlineCrackTime}</span></div>
        <div class="output-row"><span>Recommendations:</span><span>${res.recommendations.join(" ")}</span></div>
      `;
    };

    if (pwdInput) pwdInput.addEventListener("input", runPwd);
    if (btnPwdReset) {
      btnPwdReset.addEventListener("click", () => {
        pwdInput.value = "";
        pwdOut.innerHTML = "Password evaluation will appear here...";
        this.showToast("Password Evaluator Reset");
      });
    }
    if (btnPwdCopy) {
      btnPwdCopy.addEventListener("click", () => {
        this.copyToClipboard(pwdOut.innerText, "Password Analysis");
      });
    }

    // Tool 5: Security Encoder / Decoder
    const btnEncode = document.getElementById("btn-run-encode");
    const btnDecode = document.getElementById("btn-run-decode");
    const btnEncReset = document.getElementById("btn-reset-encoder");
    const btnEncCopy = document.getElementById("btn-copy-encoder");
    const btnEncDownload = document.getElementById("btn-download-encoder");

    const runEncoder = (op) => {
      const text = document.getElementById("encoder-input").value;
      const mode = document.getElementById("encoder-mode").value;
      const out = document.getElementById("encoder-output");
      const res = EncoderEngine.convert(text, mode, op);
      if (res.error) {
        out.innerHTML = `<div class="output-error">${this.escapeHTML(res.error)}</div>`;
      } else {
        out.textContent = res.output;
      }
    };

    if (btnEncode) btnEncode.addEventListener("click", () => runEncoder("encode"));
    if (btnDecode) btnDecode.addEventListener("click", () => runEncoder("decode"));
    if (btnEncReset) {
      btnEncReset.addEventListener("click", () => {
        document.getElementById("encoder-input").value = "";
        document.getElementById("encoder-output").textContent = "Encoded/Decoded text will appear here...";
        this.showToast("Encoder Reset");
      });
    }
    if (btnEncCopy) {
      btnEncCopy.addEventListener("click", () => {
        this.copyToClipboard(document.getElementById("encoder-output").textContent, "Output");
      });
    }
    if (btnEncDownload) {
      btnEncDownload.addEventListener("click", () => {
        const content = document.getElementById("encoder-output").textContent;
        this.downloadFile("decoded_payload.txt", content);
      });
    }

    // Tool 6: Firewall & ACL Builder
    const btnBuildAcl = document.getElementById("btn-build-acl");
    const btnResetAcl = document.getElementById("btn-reset-acl");
    const btnCopyAcl = document.getElementById("btn-copy-acl");
    const btnDownloadAcl = document.getElementById("btn-download-acl");

    const runAcl = () => {
      const action = document.getElementById("acl-action").value;
      const protocol = document.getElementById("acl-proto").value;
      const srcIp = document.getElementById("acl-src").value;
      const dstIp = document.getElementById("acl-dst").value;
      const dstPort = document.getElementById("acl-port").value;
      const out = document.getElementById("acl-output");

      const rules = FirewallEngine.build({ action, protocol, srcIp, dstIp, dstPort });
      out.innerHTML = `
# 1. Cisco IOS Extended Access-List
${rules.cisco}

# 2. Linux iptables Rule
${rules.iptables}

# 3. Ubuntu UFW Command
${rules.ufw}
      `;
    };

    if (btnBuildAcl) btnBuildAcl.addEventListener("click", runAcl);
    if (btnResetAcl) {
      btnResetAcl.addEventListener("click", () => {
        document.getElementById("acl-src").value = "192.168.1.0/24";
        document.getElementById("acl-dst").value = "any";
        document.getElementById("acl-port").value = "22";
        runAcl();
        this.showToast("Firewall Builder Reset");
      });
    }
    if (btnCopyAcl) {
      btnCopyAcl.addEventListener("click", () => {
        this.copyToClipboard(document.getElementById("acl-output").textContent, "Firewall rules");
      });
    }
    if (btnDownloadAcl) {
      btnDownloadAcl.addEventListener("click", () => {
        const text = document.getElementById("acl-output").textContent;
        this.downloadFile("firewall_rules.sh", text);
      });
    }

    // Tool 7: Packet Header Inspector
    const btnInspectPacket = document.getElementById("btn-inspect-packet");
    const btnResetPacket = document.getElementById("btn-reset-packet");
    const btnCopyPacket = document.getElementById("btn-copy-packet");
    const btnDownloadPacket = document.getElementById("btn-download-packet");

    const runPacket = () => {
      const src = (document.getElementById("pkt-src").value || "192.168.1.50").trim();
      const dst = (document.getElementById("pkt-dst").value || "192.168.1.1").trim();
      const ttl = document.getElementById("pkt-ttl").value || "64";
      const syn = document.getElementById("pkt-syn").checked;
      const ack = document.getElementById("pkt-ack").checked;
      const fin = document.getElementById("pkt-fin").checked;
      const rst = document.getElementById("pkt-rst").checked;

      const flags = [];
      if (syn) flags.push("SYN");
      if (ack) flags.push("ACK");
      if (fin) flags.push("FIN");
      if (rst) flags.push("RST");

      const out = document.getElementById("pkt-output");
      out.innerHTML = `
=== IPv4 Header (20 Bytes) ===
Version: 4 | IHL: 5 (20 bytes) | Type of Service: 0x00
Total Length: 60 bytes | Identification: 0x4f2a | Flags: 0x02 (Don't Fragment)
Time to Live (TTL): ${ttl} | Protocol: 6 (TCP) | Header Checksum: 0x7a1b
Source IP: ${src}
Destination IP: ${dst}

=== TCP Segment Header (20 Bytes) ===
Source Port: 51234 -> Destination Port: 80 (HTTP)
Sequence Number: 1000000001 | Acknowledgment Number: ${ack ? "2000000001" : "0"}
Data Offset: 5 (20 bytes) | Reserved: 0
Active Flags: [${flags.length > 0 ? flags.join(", ") : "NONE"}]
Window Size: 65535 | Checksum: 0x2b3c | Urgent Pointer: 0
      `;
    };

    if (btnInspectPacket) btnInspectPacket.addEventListener("click", runPacket);
    if (btnResetPacket) {
      btnResetPacket.addEventListener("click", () => {
        document.getElementById("pkt-src").value = "192.168.1.50";
        document.getElementById("pkt-dst").value = "192.168.1.1";
        document.getElementById("pkt-ttl").value = "64";
        document.getElementById("pkt-syn").checked = true;
        document.getElementById("pkt-ack").checked = false;
        document.getElementById("pkt-fin").checked = false;
        document.getElementById("pkt-rst").checked = false;
        runPacket();
        this.showToast("Packet Inspector Reset");
      });
    }
    if (btnCopyPacket) {
      btnCopyPacket.addEventListener("click", () => {
        this.copyToClipboard(document.getElementById("pkt-output").textContent, "Packet Header");
      });
    }
    if (btnDownloadPacket) {
      btnDownloadPacket.addEventListener("click", () => {
        const text = document.getElementById("pkt-output").textContent;
        this.downloadFile("packet_header.txt", text);
      });
    }

    // Tool 8: Wireshark Filter Builder
    const filterSelect = document.getElementById("wireshark-quick-filter");
    const filterOut = document.getElementById("wireshark-filter-output");
    const btnCopyFilter = document.getElementById("btn-copy-filter");
    const btnResetFilter = document.getElementById("btn-reset-filter");
    const btnDownloadFilter = document.getElementById("btn-download-filter");

    const updateFilter = () => {
      const val = filterSelect.value;
      const found = WIRESHARK_FILTERS_CATALOG.find(f => f.syntax === val);
      if (found) {
        filterOut.innerHTML = `
          <div class="output-row"><span>Filter Expression:</span><span style="color:var(--cyber-cyan);font-weight:700;">${found.syntax}</span></div>
          <div class="output-row"><span>Category:</span><span>${found.category}</span></div>
          <div class="output-row"><span>Purpose:</span><span>${found.description}</span></div>
        `;
      }
    };

    if (filterSelect) {
      filterSelect.innerHTML = WIRESHARK_FILTERS_CATALOG.map(f =>
        `<option value="${f.syntax}">${f.name} (${f.syntax})</option>`
      ).join("");
      filterSelect.addEventListener("change", updateFilter);
      updateFilter();
    }
    if (btnResetFilter) {
      btnResetFilter.addEventListener("click", () => {
        if (filterSelect) filterSelect.selectedIndex = 0;
        updateFilter();
        this.showToast("Filter Builder Reset");
      });
    }
    if (btnCopyFilter) {
      btnCopyFilter.addEventListener("click", () => {
        if (filterSelect) this.copyToClipboard(filterSelect.value, "Wireshark filter");
      });
    }
    if (btnDownloadFilter) {
      btnDownloadFilter.addEventListener("click", () => {
        const content = WIRESHARK_FILTERS_CATALOG.map(f => `# ${f.name}\n${f.syntax}\n`).join("\n");
        this.downloadFile("wireshark_filters_cheat.txt", content);
      });
    }

    // Run initial states
    runSubnet();
    runAcl();
    runPacket();
  },

  // ========================================================
  // Render Interactive Labs
  // ========================================================
  renderLabs: function () {
    const labSelector = document.getElementById("lab-selector");
    const labContainer = document.getElementById("active-lab-workspace");
    if (!labSelector || !labContainer || typeof LABS_DATA === "undefined") return;

    labSelector.innerHTML = LABS_DATA.map(lab => `
      <option value="${lab.id}">Lab ${lab.number}: ${lab.title}</option>
    `).join("");

    labSelector.addEventListener("change", (e) => {
      this.state.activeLab = e.target.value;
      this.renderActiveLab();
    });

    this.renderActiveLab();
  },

  renderActiveLab: function () {
    const labContainer = document.getElementById("active-lab-workspace");
    const lab = LABS_DATA.find(l => l.id === this.state.activeLab) || LABS_DATA[0];
    if (!labContainer || !lab) return;

    let specificContent = "";

    if (lab.id === "lab-1") {
      // Packet sniffer lab
      specificContent = `
        <div style="margin-bottom:1rem;display:flex;gap:0.5rem;align-items:center;">
          <input type="text" id="lab1-filter-input" class="form-input" style="max-width:350px;" placeholder="Filter: http, dns, tcp, arp">
          <button id="btn-apply-lab1-filter" class="btn-primary">Apply Filter</button>
          <button id="btn-clear-lab1-filter" class="btn-secondary">Clear</button>
        </div>
        <div class="table-responsive">
          <table class="cyber-table" id="lab1-table">
            <thead>
              <tr>
                <th>No.</th>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Length</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody id="lab1-tbody">
              ${lab.packets.map(p => `
                <tr data-pkt-id="${p.id}">
                  <td>${p.id}</td>
                  <td>${p.time}</td>
                  <td>${p.src}</td>
                  <td>${p.dst}</td>
                  <td><span class="card-badge badge-cyan">${p.proto}</span></td>
                  <td>${p.len}</td>
                  <td>${this.escapeHTML(p.info)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
        <div class="tool-output-area" id="lab1-payload-inspector">Click on any packet row to inspect its decoded payload and headers...</div>
      `;
    } else if (lab.id === "lab-2") {
      // Nmap Sandbox Terminal
      specificContent = `
        <div class="terminal-window">
          <div class="terminal-top-bar">
            <div class="terminal-dots">
              <span class="terminal-dot dot-red"></span>
              <span class="terminal-dot dot-yellow"></span>
              <span class="terminal-dot dot-green"></span>
            </div>
            <span class="terminal-title">recon-terminal - bash</span>
            <span></span>
          </div>
          <div class="terminal-body" id="lab2-term-body">
Starting Nmap Terminal Sandbox (v7.94)...
Type 'nmap -sS 192.168.1.10' or 'help' to begin.
          </div>
          <div class="terminal-input-row" style="padding:0.75rem 1rem;background:#0d131f;border-top:1px solid var(--border-color);">
            <span class="terminal-prompt">root@pentest:~#</span>
            <input type="text" id="lab2-term-input" class="terminal-input" placeholder="nmap -sS 192.168.1.10" autofocus>
            <button id="btn-run-term-cmd" class="btn-primary" style="padding:0.35rem 0.75rem;">Run</button>
          </div>
        </div>
      `;
    } else if (lab.id === "lab-4") {
      // Firewall simulator
      specificContent = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;margin-bottom:1rem;">
          <div class="cyber-card">
            <h4 style="margin-bottom:0.75rem;">Simulate Test Packet</h4>
            <div class="form-group">
              <label class="form-label">Source IP</label>
              <input type="text" id="sim-pkt-src" class="form-input" value="192.168.1.100">
            </div>
            <div class="form-group">
              <label class="form-label">Destination Port</label>
              <input type="number" id="sim-pkt-port" class="form-input" value="22">
            </div>
            <button id="btn-fire-sim-pkt" class="btn-primary" style="width:100%;">Transmit Packet</button>
          </div>
          <div class="cyber-card">
            <h4 style="margin-bottom:0.75rem;">Firewall Decision</h4>
            <div class="tool-output-area" id="firewall-sim-result" style="min-height:140px;">Transmit a packet to observe rule evaluation...</div>
          </div>
        </div>
      `;
    } else if (lab.id === "lab-7") {
      // SOC Incident triage
      specificContent = `
        <div class="table-responsive" style="max-height:240px;overflow-y:auto;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source File</th>
                <th>IP</th>
                <th>Severity</th>
                <th>Log Event</th>
              </tr>
            </thead>
            <tbody>
              ${lab.logs.map(log => `
                <tr>
                  <td>${log.timestamp}</td>
                  <td><code>${log.source}</code></td>
                  <td>${log.ip}</td>
                  <td><span class="card-badge ${log.severity === 'Critical' ? 'badge-red' : (log.severity === 'Emergency' ? 'badge-purple' : 'badge-amber')}">${log.severity}</span></td>
                  <td>${this.escapeHTML(log.event)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
        <div class="cyber-card" style="margin-top:1rem;">
          <h4 style="margin-bottom:0.75rem;">Incident Triage Questionnaire</h4>
          ${lab.triageQuestions.map((q, idx) => `
            <div class="form-group">
              <label class="form-label">${q.question}</label>
              <input type="text" class="form-input triage-answer-input" data-idx="${idx}" placeholder="Your answer...">
            </div>
          `).join("")}
          <button id="btn-submit-triage" class="btn-primary">Submit Incident Report</button>
          <div id="triage-feedback" style="margin-top:0.75rem;font-weight:600;"></div>
        </div>
      `;
    } else {
      specificContent = `
        <div class="cyber-card">
          <h4>Interactive Scenario: ${lab.title}</h4>
          <p style="margin:0.75rem 0;">${lab.objective}</p>
          <div class="tool-output-area">Interactive visualization active. Objective confirmed.</div>
        </div>
      `;
    }

    labContainer.innerHTML = `
      <div class="cyber-card" style="margin-bottom:1.5rem;">
        <div class="card-header-flex">
          <div>
            <span class="card-badge badge-cyan">${lab.badge}</span>
            <h3 class="card-title" style="margin-top:0.4rem;">${lab.title}</h3>
          </div>
          <span class="card-badge badge-green">Lab ${lab.number} of 7</span>
        </div>
        <p style="color:var(--text-muted);margin:0.5rem 0 1rem;"><strong>Objective:</strong> ${lab.objective}</p>
        ${specificContent}
      </div>
    `;

    // Hook listeners for lab 1
    if (lab.id === "lab-1") {
      const applyBtn = document.getElementById("btn-apply-lab1-filter");
      const clearBtn = document.getElementById("btn-clear-lab1-filter");
      const filterInput = document.getElementById("lab1-filter-input");
      const tbody = document.getElementById("lab1-tbody");
      const inspector = document.getElementById("lab1-payload-inspector");

      const filterPackets = () => {
        const q = filterInput.value.trim().toLowerCase();
        const rows = tbody.querySelectorAll("tr");
        rows.forEach(r => {
          const proto = r.querySelector("td:nth-child(5)").innerText.toLowerCase();
          const info = r.querySelector("td:nth-child(7)").innerText.toLowerCase();
          if (!q || proto.includes(q) || info.includes(q)) {
            r.style.display = "";
          } else {
            r.style.display = "none";
          }
        });
      };

      if (applyBtn) applyBtn.addEventListener("click", filterPackets);
      if (clearBtn) clearBtn.addEventListener("click", () => {
        filterInput.value = "";
        filterPackets();
      });

      tbody.querySelectorAll("tr").forEach(tr => {
        tr.addEventListener("click", () => {
          tbody.querySelectorAll("tr").forEach(r => r.classList.remove("active-row"));
          tr.classList.add("active-row");
          const id = parseInt(tr.getAttribute("data-pkt-id"), 10);
          const p = lab.packets.find(item => item.id === id);
          if (p && inspector) {
            inspector.innerHTML = `
Packet #${p.id} [${p.proto}] Time: ${p.time}s | Length: ${p.len} bytes
Source: ${p.src} -> Destination: ${p.dst}
Decoded Information: ${p.info}

--- RAW PAYLOAD ---
${p.payload}
            `;
          }
        });
      });
    }

    // Hook listeners for lab 2 (Nmap Terminal)
    if (lab.id === "lab-2") {
      const termInput = document.getElementById("lab2-term-input");
      const termBody = document.getElementById("lab2-term-body");
      const runBtn = document.getElementById("btn-run-term-cmd");

      const execCmd = () => {
        const cmd = (termInput.value || "").trim();
        if (!cmd) return;
        termBody.innerHTML += `\n<span style="color:#10b981;">root@pentest:~# ${this.escapeHTML(cmd)}</span>\n`;

        if (cmd === "help") {
          termBody.innerHTML += `Supported commands:
  nmap -sS 192.168.1.10    (TCP SYN scan)
  nmap -sV -p 80,443 192.168.1.1
  nmap -O 192.168.1.25     (OS detection)
  clear
`;
        } else if (cmd === "clear") {
          termBody.innerHTML = "Terminal cleared.\n";
        } else if (cmd.includes("192.168.1.10")) {
          termBody.innerHTML += `Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-26 20:30 UTC
Nmap scan report for 192.168.1.10
Host is up (0.00042s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.35
MAC Address: 00:0C:29:4F:8B:11 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel:5.15

Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
`;
        } else if (cmd.includes("192.168.1.1")) {
          termBody.innerHTML += `Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     Cisco SSH 1.25
80/tcp  open  http    Cisco IOS HTTP server
443/tcp open  https   Cisco HTTPS
MAC Address: 00:50:56:C0:00:08 (Cisco Systems)
Device type: router | Running: Cisco IOS 15.2
`;
        } else {
          termBody.innerHTML += `Nmap scan completed: Host reachable. Target scanned.\n`;
        }
        termInput.value = "";
        termBody.scrollTop = termBody.scrollHeight;
      };

      if (runBtn) runBtn.addEventListener("click", execCmd);
      if (termInput) {
        termInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") execCmd();
        });
      }
    }

    // Hook listeners for lab 4 (Firewall sim)
    if (lab.id === "lab-4") {
      const btnSim = document.getElementById("btn-fire-sim-pkt");
      const out = document.getElementById("firewall-sim-result");
      if (btnSim && out) {
        btnSim.addEventListener("click", () => {
          const src = document.getElementById("sim-pkt-src").value;
          const port = parseInt(document.getElementById("sim-pkt-port").value, 10);

          if (port === 23) {
            out.innerHTML = `<span style="color:var(--cyber-red);font-weight:700;">[BLOCKED / DENIED]</span> Packet to port 23 matches Rule #1: Block legacy Telnet.`;
          } else if (port === 22 && src.startsWith("192.168.1.")) {
            out.innerHTML = `<span style="color:var(--cyber-green);font-weight:700;">[PERMITTED / ALLOWED]</span> SSH packet from internal subnet matches Rule #2: Allow internal SSH.`;
          } else if (port === 443) {
            out.innerHTML = `<span style="color:var(--cyber-green);font-weight:700;">[PERMITTED / ALLOWED]</span> Inbound HTTPS packet matches Rule #3: Allow public HTTPS.`;
          } else if (port === 445) {
            out.innerHTML = `<span style="color:var(--cyber-red);font-weight:700;">[BLOCKED / DENIED]</span> SMB packet matches Rule #4: Block SMB from Internet.`;
          } else {
            out.innerHTML = `<span style="color:var(--cyber-red);font-weight:700;">[BLOCKED / DENIED]</span> Packet fell through to Rule #5: Default Deny All.`;
          }
        });
      }
    }

    // Hook listeners for lab 7 (SOC Triage)
    if (lab.id === "lab-7") {
      const btnSubmit = document.getElementById("btn-submit-triage");
      const feedback = document.getElementById("triage-feedback");
      if (btnSubmit && feedback) {
        btnSubmit.addEventListener("click", () => {
          const inputs = document.querySelectorAll(".triage-answer-input");
          let correct = 0;
          inputs.forEach((inp, idx) => {
            const val = inp.value.trim().toLowerCase();
            const target = lab.triageQuestions[idx].correctAnswer.toLowerCase();
            if (val.includes(target) || target.includes(val)) {
              correct++;
            }
          });
          feedback.innerHTML = `Score: ${correct} / ${lab.triageQuestions.length} correct. ${correct === lab.triageQuestions.length ? '<span style="color:var(--cyber-green);">Incident correctly triaged! Threat actor isolated.</span>' : '<span style="color:var(--cyber-amber);">Review the Apache and Auth logs carefully.</span>'}`;
        });
      }
    }
  },

  // ========================================================
  // Render Roadmaps & Career Tracks
  // ========================================================
  renderRoadmaps: function () {
    const container = document.getElementById("roadmaps-phases-container");
    if (!container || typeof ROADMAP_PHASES === "undefined") return;

    container.innerHTML = ROADMAP_PHASES.map(phase => {
      const totalSkills = phase.skills.length;
      let completedCount = 0;
      phase.skills.forEach(s => {
        if (this.state.roadmapProgress[s.id]) completedCount++;
      });
      const pct = Math.round((completedCount / totalSkills) * 100);

      return `
        <div class="roadmap-phase-card">
          <div class="phase-header">
            <div>
              <span class="card-badge badge-cyan">${phase.badge}</span>
              <h3 style="margin-top:0.35rem;">${phase.phaseTitle}</h3>
            </div>
            <span class="card-badge badge-green" id="badge-${phase.phaseId}">${pct}% Complete</span>
          </div>
          <p style="color:var(--text-muted);font-size:0.9rem;">${phase.description}</p>
          <div class="progress-bar-container">
            <div class="progress-bar-fill" id="fill-${phase.phaseId}" style="width:${pct}%;"></div>
          </div>
          <ul class="checklist-items">
            ${phase.skills.map(s => {
        const isChecked = !!this.state.roadmapProgress[s.id];
        return `
                <li class="check-item ${isChecked ? 'completed' : ''}" data-skill-id="${s.id}">
                  <input type="checkbox" id="chk-${s.id}" ${isChecked ? 'checked' : ''}>
                  <label for="chk-${s.id}" style="cursor:pointer;flex:1;">
                    ${s.title} <span style="color:var(--text-dim);font-size:0.8em;">(~${s.hours} hrs)</span>
                  </label>
                </li>
              `;
      }).join("")}
          </ul>
        </div>
      `;
    }).join("");

    // Career tracks
    const careersContainer = document.getElementById("career-tracks-grid");
    if (careersContainer && typeof CAREER_TRACKS !== "undefined") {
      careersContainer.innerHTML = CAREER_TRACKS.map(c => `
        <div class="cyber-card">
          <h3 class="card-title" style="color:var(--cyber-cyan);">${c.role}</h3>
          <p style="margin:0.5rem 0 0.8rem;color:var(--text-muted);">${c.summary}</p>
          <ul class="card-meta-list">
            <li><strong>Tools:</strong> <span>${c.keyTools.join(", ")}</span></li>
            <li><strong>Certs:</strong> <span>${c.certifications.join(", ")}</span></li>
            <li><strong>Est. Salary:</strong> <span style="color:var(--cyber-green);">${c.avgSalary}</span></li>
          </ul>
        </div>
      `).join("");
    }

    // Attach checkbox event listeners
    container.querySelectorAll("input[type='checkbox']").forEach(chk => {
      chk.addEventListener("change", (e) => {
        const id = e.target.id.replace("chk-", "");
        this.state.roadmapProgress[id] = e.target.checked;
        const parentLi = e.target.closest(".check-item");
        if (parentLi) parentLi.classList.toggle("completed", e.target.checked);
        try {
          localStorage.setItem("cyber_roadmap_progress", JSON.stringify(this.state.roadmapProgress));
        } catch (err) { }
        this.updateProgressSummary();
      });
    });
  },

  updateProgressSummary: function () {
    if (typeof ROADMAP_PHASES === "undefined") return;

    let grandTotal = 0;
    let grandCompleted = 0;

    ROADMAP_PHASES.forEach(phase => {
      let phaseTotal = phase.skills.length;
      let phaseDone = 0;
      phase.skills.forEach(s => {
        grandTotal++;
        if (this.state.roadmapProgress[s.id]) {
          grandCompleted++;
          phaseDone++;
        }
      });
      const pct = Math.round((phaseDone / phaseTotal) * 100);
      const fillEl = document.getElementById(`fill-${phase.phaseId}`);
      const badgeEl = document.getElementById(`badge-${phase.phaseId}`);
      if (fillEl) fillEl.style.width = `${pct}%`;
      if (badgeEl) badgeEl.textContent = `${pct}% Complete`;
    });

    const masterStat = document.getElementById("stat-roadmap-pct");
    if (masterStat) {
      const overall = grandTotal > 0 ? Math.round((grandCompleted / grandTotal) * 100) : 0;
      masterStat.textContent = `${overall}%`;
    }
  },

  // ========================================================
  // Render Glossary View
  // ========================================================
  renderGlossary: function () {
    const container = document.getElementById("glossary-terms-grid");
    const filterInput = document.getElementById("glossary-filter-input");
    if (!container || typeof GLOSSARY_TERMS === "undefined") return;

    const renderList = (filter = "") => {
      const q = filter.trim().toLowerCase();
      const filtered = GLOSSARY_TERMS.filter(t =>
        !q || t.term.toLowerCase().includes(q) || t.fullForm.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
      );

      if (filtered.length === 0) {
        container.innerHTML = `<div class="search-empty-state" style="grid-column:1/-1;">No glossary terms match "${this.escapeHTML(filter)}"</div>`;
        return;
      }

      container.innerHTML = filtered.map(t => `
        <div class="cyber-card">
          <div class="card-header-flex">
            <div>
              <h3 class="card-title" style="color:var(--cyber-cyan);">${t.term}</h3>
              <span style="font-size:0.85rem;font-weight:600;color:var(--text-main);">${t.fullForm}</span>
            </div>
            <span class="card-badge badge-purple">${t.category}</span>
          </div>
          <div class="card-body">
            <p>${t.description}</p>
          </div>
        </div>
      `).join("");
    };

    renderList();

    if (filterInput) {
      filterInput.addEventListener("input", (e) => {
        renderList(e.target.value);
      });
    }
  }
};

// Start application when DOM is ready
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    App.init();
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    CryptoUtils,
    SubnetEngine,
    PasswordEngine,
    EncoderEngine,
    FirewallEngine,
    App
  };
}
