# -*- coding: utf-8 -*-
r"""
解密 Office 檔（有密碼鎖的 Excel / Word / PowerPoint）。

特色：只用 Python「內建」功能，不用安裝任何套件（沒有 msoffcrypto、沒有 cryptography 也能跑）。

支援的鎖：
  - 新版 .xlsx / .docx / .pptx（Office 2007 以後）：Agile（AES-CBC）、Standard（AES-ECB）
  - 舊版 .xls（Excel 97-2003）：RC4 CryptoAPI、RC4
  不支援：很舊的 XOR 混淆（.xls，少見）、憑證加密 → 會明白說「不支援」，不會亂解。

用法：
  解密（開鎖）：
    python 解密excel.py <加密檔> <輸出檔> --密碼 你的密碼
    python 解密excel.py <加密檔> <輸出檔> --config config.json   # 從 config.json 讀 password 欄位
  加密（上鎖，把未加密的 .xlsx/.docx/.pptx 設密碼）：
    python 解密excel.py <未加密檔> <輸出檔> --上鎖 --密碼 你的密碼
    python 解密excel.py <未加密檔> <輸出檔> --上鎖 --config config.json
  其他：
    python 解密excel.py --檢查 <檔>              # 只看它是不是加密、哪種鎖
    python 解密excel.py --自我測試 <測試資料夾>  # 用官方公開測試檔驗證自己（開發用）

說明：
  - 密碼永遠不會被印出來，也不會寫進任何檔。
  - 解不開時會說是「密碼錯」還是「這種鎖不支援」，不會給你一個壞檔。
"""
import sys
import io
import json
import struct
import hashlib

# ======================================================================
# 一、AES（純 Python，只做解密：支援 128/192/256 位元，CBC 與 ECB）
# ======================================================================
_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d)


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _mul(a, b):
    """GF(2^8) 乘法。"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [_SBOX[b] for b in t]               # SubWord
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_round_key(s, w, rnd):
    for c in range(4):
        wk = w[rnd * 4 + c]
        for r in range(4):
            s[r][c] ^= wk[r]


def _decrypt_block(block, w, nr):
    # state 以行列存放（column-major，和 AES 規格一致）
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        # InvShiftRows
        for r in range(1, 4):
            s[r] = s[r][-r:] + s[r][:-r]
        # InvSubBytes
        for r in range(4):
            for c in range(4):
                s[r][c] = _INV_SBOX[s[r][c]]
        _add_round_key(s, w, rnd)
        # InvMixColumns
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            s[0][c] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            s[1][c] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            s[2][c] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            s[3][c] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    for r in range(4):
        for c in range(4):
            s[r][c] = _INV_SBOX[s[r][c]]
    _add_round_key(s, w, 0)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_decrypt_ecb(data, key):
    w, nr = _key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _decrypt_block(data[i:i + 16], w, nr)
    return bytes(out)


def aes_decrypt_cbc(data, key, iv):
    w, nr = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, w, nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _encrypt_block(block, w, nr):
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            s[0][c] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
            s[1][c] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
            s[2][c] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
            s[3][c] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)
        _add_round_key(s, w, rnd)
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    _add_round_key(s, w, nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_encrypt_cbc(data, key, iv):
    w, nr = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, w, nr)
        out += enc
        prev = enc
    return bytes(out)


# ======================================================================
# 二、RC4（純 Python）
# ======================================================================
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(ch ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


# ======================================================================
# 三、OLE / 複合檔（CFB）讀取器 ＋ 同大小就地覆寫
# ======================================================================
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC


class OleError(Exception):
    pass


class Ole:
    def __init__(self, data):
        self.data = bytearray(data)
        d = self.data
        if bytes(d[0:8]) != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise OleError("不是 OLE 複合檔")
        self.major = struct.unpack_from("<H", d, 26)[0]
        self.sector_size = 1 << struct.unpack_from("<H", d, 30)[0]
        self.mini_size = 1 << struct.unpack_from("<H", d, 32)[0]
        num_fat = struct.unpack_from("<I", d, 44)[0]
        self.first_dir = struct.unpack_from("<I", d, 48)[0]
        self.mini_cutoff = struct.unpack_from("<I", d, 56)[0]
        first_minifat = struct.unpack_from("<I", d, 60)[0]
        first_difat = struct.unpack_from("<I", d, 68)[0]
        num_difat = struct.unpack_from("<I", d, 72)[0]

        # DIFAT：列出哪些 sector 是 FAT
        difat = list(struct.unpack_from("<109I", d, 76))
        sid = first_difat
        per = self.sector_size // 4
        guard = 0
        while sid not in (_ENDOFCHAIN, _FREESECT) and num_difat > 0:
            sec = self._raw(sid)
            vals = struct.unpack("<%dI" % per, sec)
            difat += list(vals[:-1])
            sid = vals[-1]
            guard += 1
            if guard > num_difat + 2:
                break
        difat = [s for s in difat[:num_fat] if s != _FREESECT]

        # FAT：整張配置表
        fat = []
        for s in difat:
            fat += list(struct.unpack("<%dI" % per, self._raw(s)))
        self.fat = fat

        # 目錄
        dir_bytes = self._read_chain(self.first_dir)
        self.entries = {}
        self.root = None
        for off in range(0, len(dir_bytes), 128):
            e = dir_bytes[off:off + 128]
            if len(e) < 128:
                break
            name_len = struct.unpack_from("<H", e, 64)[0]
            obj_type = e[66]
            if obj_type == 0:  # 空
                continue
            name = e[0:max(0, name_len - 2)].decode("utf-16-le", "replace")
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<Q", e, 120)[0]
            if self.major == 3:
                size &= 0xFFFFFFFF
            info = {"name": name, "type": obj_type, "start": start, "size": size}
            if obj_type == 5:
                self.root = info
            else:
                self.entries[name] = info

        # mini FAT ＋ mini stream
        self.minifat = []
        sid = first_minifat
        guard = 0
        while sid not in (_ENDOFCHAIN, _FREESECT):
            self.minifat += list(struct.unpack("<%dI" % per, self._raw(sid)))
            sid = self.fat[sid]
            guard += 1
            if guard > len(self.fat) + 2:
                break
        self.mini_stream = b""
        if self.root and self.root["size"] > 0:
            self.mini_stream = self._read_chain(self.root["start"])[:self.root["size"]]

    def _raw(self, sid):
        off = (sid + 1) * self.sector_size
        return bytes(self.data[off:off + self.sector_size])

    def _read_chain(self, start):
        out = bytearray()
        sid = start
        guard = 0
        while sid not in (_ENDOFCHAIN, _FREESECT):
            out += self._raw(sid)
            sid = self.fat[sid]
            guard += 1
            if guard > len(self.fat) + 2:
                raise OleError("FAT 鏈結異常")
        return bytes(out)

    def open(self, name):
        e = self.entries.get(name)
        if e is None:
            raise OleError("找不到串流：%s" % name)
        if e["size"] >= self.mini_cutoff:
            return self._read_chain(e["start"])[:e["size"]]
        # 小串流走 mini FAT
        out = bytearray()
        sid = e["start"]
        guard = 0
        while sid not in (_ENDOFCHAIN, _FREESECT):
            off = sid * self.mini_size
            out += self.mini_stream[off:off + self.mini_size]
            sid = self.minifat[sid]
            guard += 1
            if guard > len(self.minifat) + 2:
                raise OleError("mini FAT 鏈結異常")
        return bytes(out[:e["size"]])

    def has(self, name):
        return name in self.entries

    def write_inplace(self, name, newdata):
        """把串流內容就地換成 newdata（長度必須一樣）。只支援走大 FAT 的串流。"""
        e = self.entries.get(name)
        if e is None:
            raise OleError("找不到串流：%s" % name)
        if len(newdata) != e["size"]:
            raise OleError("就地覆寫要求長度相同（舊 %d、新 %d）" % (e["size"], len(newdata)))
        if e["size"] < self.mini_cutoff:
            raise OleError("此串流存在 mini stream，暫不支援就地覆寫")
        sid = e["start"]
        pos = 0
        guard = 0
        while sid not in (_ENDOFCHAIN, _FREESECT):
            off = (sid + 1) * self.sector_size
            chunk = newdata[pos:pos + self.sector_size]
            self.data[off:off + len(chunk)] = chunk
            pos += self.sector_size
            sid = self.fat[sid]
            guard += 1
            if guard > len(self.fat) + 2:
                raise OleError("FAT 鏈結異常")

    def tobytes(self):
        return bytes(self.data)


# ======================================================================
# 四、新版 OOXML（.xlsx/.docx/.pptx）解密
# ======================================================================
_HASH = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
         "SHA384": hashlib.sha384, "SHA512": hashlib.sha512}

_BLK_VERIFIER_INPUT = bytes([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
_BLK_VERIFIER_VALUE = bytes([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])
_BLK_KEY_VALUE = bytes([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])


def _norm(buf, n, pad=b"\x36"):
    return buf[:n] if len(buf) >= n else buf + pad * (n - len(buf))


class WrongPassword(Exception):
    pass


class NotSupported(Exception):
    pass


def _agile_iter_hash(password, salt, hash_name, spin):
    h = _HASH.get(hash_name, hashlib.sha1)
    d = h(salt + password.encode("utf-16-le")).digest()
    for i in range(spin):
        d = h(struct.pack("<I", i) + d).digest()
    return d


def _agile_key(d, blk, hash_name, key_bits):
    h = _HASH.get(hash_name, hashlib.sha1)
    return h(d + blk).digest()[: key_bits // 8]


def _decrypt_ooxml_agile(ole, password):
    import base64
    from xml.dom.minidom import parseString
    info = ole.open("EncryptionInfo")
    xml = parseString(info[8:])

    def g(tag, attr):
        return xml.getElementsByTagName(tag)[0].getAttribute(attr)

    key_salt = base64.b64decode(g("keyData", "saltValue"))
    key_hash = g("keyData", "hashAlgorithm")
    pw_node = xml.getElementsByTagNameNS(
        "http://schemas.microsoft.com/office/2006/keyEncryptor/password",
        "encryptedKey")[0]
    spin = int(pw_node.getAttribute("spinCount"))
    pw_salt = base64.b64decode(pw_node.getAttribute("saltValue"))
    pw_hash = pw_node.getAttribute("hashAlgorithm")
    key_bits = int(pw_node.getAttribute("keyBits"))
    enc_key_value = base64.b64decode(pw_node.getAttribute("encryptedKeyValue"))
    enc_vin = base64.b64decode(pw_node.getAttribute("encryptedVerifierHashInput"))
    enc_vval = base64.b64decode(pw_node.getAttribute("encryptedVerifierHashValue"))

    d = _agile_iter_hash(password, pw_salt, pw_hash, spin)
    # 驗密碼
    k1 = _agile_key(d, _BLK_VERIFIER_INPUT, pw_hash, key_bits)
    k2 = _agile_key(d, _BLK_VERIFIER_VALUE, pw_hash, key_bits)
    hcalc = _HASH.get(pw_hash, hashlib.sha1)
    actual = hcalc(aes_decrypt_cbc(enc_vin, k1, pw_salt)).digest()
    expected = aes_decrypt_cbc(enc_vval, k2, pw_salt)[: hcalc().digest_size]
    if actual != expected:
        raise WrongPassword()

    # 取出真正的檔案金鑰
    k3 = _agile_key(d, _BLK_KEY_VALUE, pw_hash, key_bits)
    secret = aes_decrypt_cbc(enc_key_value, k3, pw_salt)

    pkg = ole.open("EncryptedPackage")
    total = struct.unpack_from("<Q", pkg, 0)[0]
    h = _HASH.get(key_hash, hashlib.sha1)
    out = bytearray()
    body = pkg[8:]
    for i in range(0, len(body), 4096):
        seg = body[i:i + 4096]
        iv = h(key_salt + struct.pack("<I", i // 4096)).digest()[:16]
        out += aes_decrypt_cbc(seg, secret, iv)
    return bytes(out[:total])


def _decrypt_ooxml_standard(ole, password):
    info = ole.open("EncryptionInfo")
    blob = io.BytesIO(info[4:])  # 跳過 version(4)
    struct.unpack("<I", blob.read(4))  # headerFlags
    hsize = struct.unpack("<I", blob.read(4))[0]
    hdr = io.BytesIO(blob.read(hsize))
    struct.unpack("<I", hdr.read(4))  # flags
    struct.unpack("<I", hdr.read(4))  # sizeExtra
    struct.unpack("<I", hdr.read(4))  # algId
    struct.unpack("<I", hdr.read(4))  # algIdHash
    key_size = struct.unpack("<I", hdr.read(4))[0]
    rest = io.BytesIO(blob.read())
    struct.unpack("<I", rest.read(4))  # saltSize
    salt = rest.read(16)
    enc_verifier = rest.read(16)
    struct.unpack("<I", rest.read(4))  # verifierHashSize
    enc_verifier_hash = rest.read(32)

    pw = password.encode("utf-16-le")
    h = hashlib.sha1(salt + pw).digest()
    for i in range(50000):
        h = hashlib.sha1(struct.pack("<I", i) + h).digest()
    hfinal = hashlib.sha1(h + struct.pack("<I", 0)).digest()
    cb = key_size // 8
    x1 = hashlib.sha1(bytes(b ^ 0x36 for b in hfinal) + b"\x36" * (64 - len(hfinal))).digest()
    x2 = hashlib.sha1(bytes(b ^ 0x5c for b in hfinal) + b"\x5c" * (64 - len(hfinal))).digest()
    key = (x1 + x2)[:cb]

    verifier = aes_decrypt_ecb(enc_verifier, key)
    vhash = aes_decrypt_ecb(enc_verifier_hash, key)[:20]
    if hashlib.sha1(verifier).digest() != vhash:
        raise WrongPassword()

    pkg = ole.open("EncryptedPackage")
    total = struct.unpack_from("<I", pkg, 0)[0]
    return aes_decrypt_ecb(pkg[8:], key)[:total]


# ======================================================================
# 五、舊版 .xls 解密
# ======================================================================
_REC = {"EOF": 10, "FilePass": 47, "BoundSheet8": 133, "BOF": 2057,
        "InterfaceHdr": 225, "UsrExcl": 404, "FileLock": 405,
        "RRDInfo": 406, "RRDHead": 312}


def _xls_makekey_cryptoapi(password, salt, key_len, block):
    h0 = hashlib.sha1(salt + password.encode("utf-16-le")).digest()
    hfinal = hashlib.sha1(h0 + struct.pack("<I", block)).digest()
    if key_len == 40:
        return hfinal[:5] + b"\x00" * 11
    return hfinal[: key_len // 8]


def _xls_makekey_rc4(password, salt, block):
    h0 = hashlib.md5(password.encode("utf-16-le")).digest()
    inter = (h0[:5] + salt) * 16
    h1 = hashlib.md5(inter).digest()
    return hashlib.md5(h1[:5] + struct.pack("<I", block)).digest()[:16]


def _decrypt_xls(ole, password):
    stream_name = "Workbook" if ole.has("Workbook") else ("Book" if ole.has("Book") else None)
    if stream_name is None:
        raise OleError("這個 .xls 裡找不到 Workbook 串流")
    wb = ole.open(stream_name)
    buf = io.BytesIO(wb)

    # 讀 BOF
    num = struct.unpack("<H", buf.read(2))[0]
    if num != _REC["BOF"]:
        raise OleError("不是有效的 .xls（開頭不是 BOF）")
    size = struct.unpack("<H", buf.read(2))[0]
    buf.read(size)
    # 找 FilePass
    while True:
        h = buf.read(4)
        if len(h) < 4:
            raise NotSupported("這個 .xls 沒有密碼鎖（找不到 FilePass）")
        num, size = struct.unpack("<HH", h)
        if num == _REC["FilePass"]:
            break
        buf.read(size)

    enc_type = struct.unpack("<H", buf.read(2))[0]
    einfo = io.BytesIO(buf.read(size - 2))

    if enc_type == 0x0000:
        raise NotSupported("這個 .xls 用的是很舊的 XOR 混淆鎖，本工具不支援；請找 IT 的工具。")
    if enc_type != 0x0001:
        raise NotSupported("未知的 .xls 加密類型 0x%04X" % enc_type)

    vmaj, vmin = struct.unpack("<HH", einfo.read(4))
    mode = None
    if vmaj == 1 and vmin == 1:
        mode = "rc4"
        salt = einfo.read(16)
        enc_verifier = einfo.read(16)
        enc_verifier_hash = einfo.read(16)
        key = _xls_makekey_rc4(password, salt, 0)
        ks = rc4(key, enc_verifier + enc_verifier_hash)
        if hashlib.md5(ks[:16]).digest() != ks[16:32]:
            raise WrongPassword()
        key_len = None
    elif vmaj in (2, 3, 4) and vmin == 2:
        mode = "rc4_cryptoapi"
        einfo.read(4)  # flags
        hsize = struct.unpack("<I", einfo.read(4))[0]
        hdr = io.BytesIO(einfo.read(hsize))
        hdr.read(4 * 4)  # flags, sizeExtra, algId, algIdHash
        key_len = struct.unpack("<I", hdr.read(4))[0]
        if key_len == 0:
            key_len = 0x28
        rest = io.BytesIO(einfo.read())
        rest.read(4)  # saltSize
        salt = rest.read(16)
        enc_verifier = rest.read(16)
        rest.read(4)  # verifierHashSize
        enc_verifier_hash = rest.read(20)
        key = _xls_makekey_cryptoapi(password, salt, key_len, 0)
        ks = rc4(key, enc_verifier + enc_verifier_hash)
        if hashlib.sha1(ks[:16]).digest() != ks[16:36]:
            raise WrongPassword()
    else:
        raise NotSupported(".xls 加密版本 %d.%d 不支援" % (vmaj, vmin))

    # 重建 Workbook：把明文位置標起來、其餘照位置用 RC4 解
    buf.seek(0)
    plain = []                 # 每個 byte：實際值，或 -1 代表「用解出來的」
    enc_stream = io.BytesIO()  # 全長資料，明文位置填 0（讓 keystream 位置對齊）
    while True:
        h = buf.read(4)
        if not h:
            break
        num, size = struct.unpack("<HH", h)
        rec = buf.read(size)
        if num == _REC["FilePass"]:
            plain += [0, 0] + list(struct.pack("<H", size)) + [0] * size
            enc_stream.write(b"\x00" * (4 + size))
        elif num in (_REC["BOF"], _REC["InterfaceHdr"], _REC["UsrExcl"],
                     _REC["FileLock"], _REC["RRDInfo"], _REC["RRDHead"]):
            plain += list(struct.pack("<HH", num, size)) + list(rec)
            enc_stream.write(b"\x00" * (4 + size))
        elif num == _REC["BoundSheet8"]:
            plain += list(struct.pack("<HH", num, size)) + list(rec[:4]) + [-1] * (size - 4)
            enc_stream.write(b"\x00" * 8 + rec[4:])
        else:
            plain += list(struct.pack("<HH", num, size)) + [-1] * size
            enc_stream.write(b"\x00" * 4 + rec)

    data = enc_stream.getvalue()
    dec = bytearray()
    block = 0
    for i in range(0, len(data), 1024):
        if mode == "rc4":
            k = _xls_makekey_rc4(password, salt, block)
        else:
            k = _xls_makekey_cryptoapi(password, salt, key_len, block)
        dec += rc4(k, data[i:i + 1024])
        block += 1

    out = bytearray(dec)
    for idx, c in enumerate(plain):
        if c != -1:
            out[idx] = c
    ole.write_inplace(stream_name, bytes(out))
    return ole.tobytes()


# ======================================================================
# 五之二、把檔案「重新上鎖」（加密成新版 Agile／AES-256 ＋ SHA512）
# ======================================================================
import os as _os
import hmac as _hmac
from datetime import datetime as _dt

_BLK_INTEGRITY1 = bytes([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
_BLK_INTEGRITY2 = bytes([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _roundup(n, b):
    return ((n + b - 1) // b) * b


def _enc_b64(b):
    import base64
    return base64.b64encode(b).decode("ascii")


def _build_encryption_info(plain, password):
    """回傳 (EncryptionInfo 位元組, EncryptedPackage 位元組)。固定 AES-256 + SHA512。"""
    SALT = 16
    BLK = 16
    KEYBITS = 256
    HASHSZ = 64
    SPIN = 100000
    key_salt = _os.urandom(SALT)
    pw_salt = _os.urandom(SALT)

    d = _agile_iter_hash(password, pw_salt, "SHA512", SPIN)
    k1 = _agile_key(d, _BLK_VERIFIER_INPUT, "SHA512", KEYBITS)
    k2 = _agile_key(d, _BLK_VERIFIER_VALUE, "SHA512", KEYBITS)
    k3 = _agile_key(d, _BLK_KEY_VALUE, "SHA512", KEYBITS)

    verifier_input = _os.urandom(SALT)
    enc_vin = aes_encrypt_cbc(verifier_input, k1, pw_salt)
    hashed = hashlib.sha512(verifier_input).digest()
    hashed = hashed + b"\x00" * (_roundup(len(hashed), BLK) - len(hashed))
    enc_vval = aes_encrypt_cbc(hashed, k2, pw_salt)

    secret = _norm(_os.urandom(SALT), KEYBITS // 8)  # 16 隨機 + 補到 32（和官方相同）
    enc_key_value = aes_encrypt_cbc(secret, k3, pw_salt)

    # 加密內容（每 4096 位元組一段，各段自己的 IV）
    out = io.BytesIO()
    for i in range(0, len(plain), 4096):
        seg = plain[i:i + 4096]
        iv = _norm(hashlib.sha512(key_salt + struct.pack("<I", i // 4096)).digest(), SALT, b"\x00")
        if len(seg) % BLK:
            seg = seg + b"\x00" * (_roundup(len(seg), BLK) - len(seg))
        out.write(aes_encrypt_cbc(seg, secret, iv))
    enc_payload = struct.pack("<Q", len(plain)) + out.getvalue()

    # 完整性 HMAC
    isalt = _os.urandom(HASHSZ)
    iv1 = _norm(hashlib.sha512(key_salt + _BLK_INTEGRITY1).digest(), BLK, b"\x00")
    iv2 = _norm(hashlib.sha512(key_salt + _BLK_INTEGRITY2).digest(), BLK, b"\x00")
    enc_hmac_key = aes_encrypt_cbc(isalt, secret, iv1)
    hv = _hmac.new(isalt, enc_payload, hashlib.sha512).digest()
    hv = hv + b"\x00" * (_roundup(len(hv), BLK) - len(hv))
    enc_hmac_val = aes_encrypt_cbc(hv, secret, iv2)

    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption"'
        ' xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"'
        ' xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">'
        '<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64"'
        ' cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512"'
        ' saltValue="%s"/>'
        '<dataIntegrity encryptedHmacKey="%s" encryptedHmacValue="%s"/>'
        '<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
        '<p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64"'
        ' cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512"'
        ' saltValue="%s" encryptedVerifierHashInput="%s" encryptedVerifierHashValue="%s"'
        ' encryptedKeyValue="%s"/></keyEncryptor></keyEncryptors></encryption>'
    ) % (_enc_b64(key_salt), _enc_b64(enc_hmac_key), _enc_b64(enc_hmac_val),
         _enc_b64(pw_salt), _enc_b64(enc_vin), _enc_b64(enc_vval), _enc_b64(enc_key_value))
    info = struct.pack("<HHI", 4, 4, 0x40) + xml.encode("utf-8")
    return info, enc_payload


# ---- 產生 OLE 容器（移植自 msoffcrypto，只用內建函式） ----
_ENDc = 0xFFFFFFFE
_FREEc = 0xFFFFFFFF
_FATc = 0xFFFFFFFD
_DIFc = 0xFFFFFFFC


def _dt2filetime(dt):
    return int((dt - _dt(1601, 1, 1)).total_seconds() * 10000000)


_DC_Version = b"\x3c\x00\x00\x00\x4d\x00\x69\x00\x63\x00\x72\x00\x6f\x00\x73\x00\x6f\x00\x66\x00\x74\x00\x2e\x00\x43\x00\x6f\x00\x6e\x00\x74\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x72\x00\x2e\x00\x44\x00\x61\x00\x74\x00\x61\x00\x53\x00\x70\x00\x61\x00\x63\x00\x65\x00\x73\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00"
_DC_Primary = b"\x58\x00\x00\x00\x01\x00\x00\x00\x4c\x00\x00\x00\x7b\x00\x46\x00\x46\x00\x39\x00\x41\x00\x33\x00\x46\x00\x30\x00\x33\x00\x2d\x00\x35\x00\x36\x00\x45\x00\x46\x00\x2d\x00\x34\x00\x36\x00\x31\x00\x33\x00\x2d\x00\x42\x00\x44\x00\x44\x00\x35\x00\x2d\x00\x35\x00\x41\x00\x34\x00\x31\x00\x43\x00\x31\x00\x44\x00\x30\x00\x37\x00\x32\x00\x34\x00\x36\x00\x7d\x00\x4e\x00\x00\x00\x4d\x00\x69\x00\x63\x00\x72\x00\x6f\x00\x73\x00\x6f\x00\x66\x00\x74\x00\x2e\x00\x43\x00\x6f\x00\x6e\x00\x74\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x72\x00\x2e\x00\x45\x00\x6e\x00\x63\x00\x72\x00\x79\x00\x70\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x54\x00\x72\x00\x61\x00\x6e\x00\x73\x00\x66\x00\x6f\x00\x72\x00\x6d\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00"
_DC_DataSpaceMap = b"\x08\x00\x00\x00\x01\x00\x00\x00\x68\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x45\x00\x6e\x00\x63\x00\x72\x00\x79\x00\x70\x00\x74\x00\x65\x00\x64\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x61\x00\x67\x00\x65\x00\x32\x00\x00\x00\x53\x00\x74\x00\x72\x00\x6f\x00\x6e\x00\x67\x00\x45\x00\x6e\x00\x63\x00\x72\x00\x79\x00\x70\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x44\x00\x61\x00\x74\x00\x61\x00\x53\x00\x70\x00\x61\x00\x63\x00\x65\x00\x00\x00"
_DC_StrongDS = b"\x08\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x53\x00\x74\x00\x72\x00\x6f\x00\x6e\x00\x67\x00\x45\x00\x6e\x00\x63\x00\x72\x00\x79\x00\x70\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x54\x00\x72\x00\x61\x00\x6e\x00\x73\x00\x66\x00\x6f\x00\x72\x00\x6d\x00\x00\x00"


def _blocks(x, b):
    return (x + b - 1) // b


def _dir_entry(name, typ, color, left=_FREEc, right=_FREEc, child=_FREEc, content=b"", ft=0):
    return {"name": name, "type": typ, "color": color, "left": left, "right": right,
            "child": child, "content": content, "ft": ft, "start": 0}


def _write_dir_header(obuf, d):
    n16 = d["name"].encode("utf-16-le")
    size = len(n16) + 2
    obuf.write(n16 + b"\x00\x00")
    obuf.write(b"\x00" * (64 - size))
    obuf.write(struct.pack("<H", size if size > 2 else 0))
    obuf.write(struct.pack("<BBIII", d["type"], d["color"], d["left"], d["right"], d["child"]))
    obuf.write(b"\x00" * 16)       # CLSID
    obuf.write(struct.pack("<I", 0))  # state bits
    obuf.write(struct.pack("<II", d["ft"] & 0xFFFFFFFF, d["ft"] >> 32))  # ctime
    obuf.write(struct.pack("<II", d["ft"] & 0xFFFFFFFF, d["ft"] >> 32))  # mtime
    obuf.write(struct.pack("<IQ", d["start"], len(d["content"])))


def _write_fat(obuf, entries, block_size):
    v = 0
    start = obuf.tell()
    max_n = block_size // 4
    for e in entries:
        if e <= 0xFFFFFFFA:
            for _j in range(1, e):
                v += 1
                obuf.write(struct.pack("<I", v))
            obuf.write(struct.pack("<I", _ENDc))
        else:
            obuf.write(struct.pack("<I", e))
        v += 1
    obuf.write(struct.pack("<I", _FREEc) * (max_n - v))
    assert obuf.tell() - start == block_size


def build_encrypted_ole(enc_payload, enc_info):
    """把 EncryptedPackage + EncryptionInfo 包成 OLE 複合檔。回傳位元組。"""
    SS = 512
    ft = _dt2filetime(_dt.now())
    # 目錄（順序固定，和官方相同）
    R, EP, DS, VER, DSM, DSI, SEDS, TI, SET, PRI, EI = range(11)
    dirs = [
        _dir_entry("Root Entry", 5, 0, child=EI, ft=ft),
        _dir_entry("EncryptedPackage", 2, 0, ft=ft),
        _dir_entry("\x06DataSpaces", 1, 0, child=DSM, ft=ft),
        _dir_entry("Version", 2, 1, content=_DC_Version, ft=ft),
        _dir_entry("DataSpaceMap", 2, 1, left=VER, right=DSI, content=_DC_DataSpaceMap, ft=ft),
        _dir_entry("DataSpaceInfo", 1, 1, right=TI, child=SEDS, ft=ft),
        _dir_entry("StrongEncryptionDataSpace", 2, 1, content=_DC_StrongDS, ft=ft),
        _dir_entry("TransformInfo", 1, 0, child=SET, ft=ft),
        _dir_entry("StrongEncryptionTransform", 1, 1, child=PRI, ft=ft),
        _dir_entry("\x06Primary", 2, 1, content=_DC_Primary, ft=ft),
        _dir_entry("EncryptionInfo", 2, 1, left=DS, right=EP, content=enc_info, ft=ft),
    ]
    dirs[EP]["content"] = enc_payload

    # 版面：小於 4096 的串流走 mini FAT，較大的走大 FAT（EncryptedPackage 依大小決定）
    ep_big = len(enc_payload) >= 4096
    mini_streams = [d for d in dirs if d["type"] == 2 and 0 < len(d["content"]) < 4096]
    mini_sectors = []
    pos = 0
    for s in mini_streams:
        n = _blocks(len(s["content"]), 64)
        mini_sectors.append(n)
        s["start"] = pos
        pos += n
    mini_num = pos
    mini_data_sectors = _blocks(mini_num, SS // 64)
    num_minifat_sectors = 1
    if mini_num > (SS // 4):
        raise NotSupported("內部版面過大，暫不支援")
    dir_sectors = _blocks(len(dirs), 4)
    ep_sectors = _blocks(len(enc_payload), SS) if ep_big else 0
    content_sectors = num_minifat_sectors + dir_sectors + mini_data_sectors + ep_sectors

    # 算 FAT/DIFAT 需要幾個 sector
    numInFat = SS // 4
    difat_n = fat_n = 0
    for _ in range(10):
        a = _blocks(difat_n + fat_n + content_sectors, numInFat)
        b = 0 if a <= 109 else _blocks(a - 109, numInFat - 1)
        if b == difat_n and a == fat_n:
            break
        difat_n, fat_n = b, a

    difat_pos = 0
    fat_pos = difat_pos + difat_n
    minifat_pos = fat_pos + fat_n
    dir_pos = minifat_pos + num_minifat_sectors
    mini_data_pos = dir_pos + dir_sectors
    ep_pos = mini_data_pos + mini_data_sectors
    total_sectors = difat_n + fat_n + content_sectors
    total_size = SS + total_sectors * SS

    dirs[R]["start"] = mini_data_pos
    dirs[R]["content"] = b"\x00" * (64 * mini_num)
    if ep_big:
        dirs[EP]["start"] = ep_pos

    obuf = io.BytesIO(b"\x00" * total_size)
    # 檔頭
    obuf.seek(0)
    obuf.write(_OLE_MAGIC + b"\x00" * 16)
    obuf.write(struct.pack("<HHHHHHHHIIIIIIIII",
                           0x003E, 3, 0xFFFE, 9, 6, 0, 0, 0,
                           0, fat_n, dir_pos, 0, 0x1000,
                           minifat_pos, num_minifat_sectors,
                           (difat_pos if difat_n > 0 else _ENDc), difat_n))
    difat = [fat_pos + i for i in range(min(fat_n, 109))]
    for i in range(109):
        obuf.write(struct.pack("<I", difat[i] if i < len(difat) else _FREEc))

    # FAT：DIF 區、FAT 區，再來各內容串流的鏈（順序要和實際擺放一致）
    obuf.seek(SS + fat_pos * SS)
    chains = [num_minifat_sectors, dir_sectors, mini_data_sectors]
    if ep_big:
        chains.append(ep_sectors)
    fat_entries = ([_DIFc] * difat_n) + ([_FATc] * fat_n) + chains
    _write_fat(obuf, fat_entries, fat_n * SS)

    # mini FAT
    obuf.seek(SS + minifat_pos * SS)
    _write_fat(obuf, mini_sectors, num_minifat_sectors * SS)

    # 目錄
    obuf.seek(SS + dir_pos * SS)
    for d in dirs:
        _write_dir_header(obuf, d)

    # 內容：小串流進 mini 區，大串流（EncryptedPackage）進大 FAT 區
    mini_data_off = SS + mini_data_pos * SS
    for d in dirs:
        c = d["content"]
        if not c:
            continue
        if d["type"] == 2 and len(c) < 4096:   # 小串流進 mini 區；Root 和大串流進大 FAT
            obuf.seek(mini_data_off + d["start"] * 64)
        else:
            obuf.seek(SS + d["start"] * SS)
        obuf.write(c)
    return obuf.getvalue()


def encrypt_file(in_path, out_path, password):
    """把未加密的 .xlsx/.docx/.pptx 上鎖成新版 Agile/AES 加密檔。"""
    with open(in_path, "rb") as f:
        plain = f.read()
    if plain[:4] != b"PK\x03\x04":
        raise NotSupported("只能把「未加密」的新版 Office 檔（.xlsx/.docx/.pptx）上鎖；這個檔不是。")
    info, payload = _build_encryption_info(plain, password)
    ole = build_encrypted_ole(payload, info)
    with open(out_path, "wb") as f:
        f.write(ole)
    return True


# ======================================================================
# 六、對外主流程
# ======================================================================
def sniff(path):
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:4] == b"PK\x03\x04":
        return "zip"        # 已是未加密的 xlsx/docx
    if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    return "unknown"


def describe(path):
    kind = sniff(path)
    if kind == "zip":
        return "沒有加密（已經是可直接打開的 Office 檔）"
    if kind == "unknown":
        return "認不得這個檔（不是 Office 檔？）"
    with open(path, "rb") as f:
        ole = Ole(f.read())
    if ole.has("EncryptionInfo") and ole.has("EncryptedPackage"):
        info = ole.open("EncryptionInfo")
        vmaj, vmin = struct.unpack_from("<HH", info, 0)
        if (vmaj, vmin) == (4, 4):
            return "新版加密（Agile／AES）"
        return "新版加密（Standard／AES）"
    if ole.has("Workbook") or ole.has("Book"):
        return "舊版 .xls（可能有密碼鎖）"
    return "OLE 檔，但認不出加密方式"


def decrypt_file(in_path, out_path, password):
    """解密；成功回 True。密碼錯丟 WrongPassword，鎖不支援丟 NotSupported。"""
    kind = sniff(in_path)
    if kind == "zip":
        raise NotSupported("這個檔沒有加密，不用解。")
    if kind != "ole":
        raise NotSupported("認不得這個檔，不像 Office 檔。")
    with open(in_path, "rb") as f:
        ole = Ole(f.read())
    if ole.has("EncryptionInfo") and ole.has("EncryptedPackage"):
        info = ole.open("EncryptionInfo")
        vmaj, vmin = struct.unpack_from("<HH", info, 0)
        if (vmaj, vmin) == (4, 4):
            out = _decrypt_ooxml_agile(ole, password)
        elif vmin == 2:
            out = _decrypt_ooxml_standard(ole, password)
        else:
            raise NotSupported("新版加密版本 %d.%d 不支援" % (vmaj, vmin))
        # 驗證：解出來應該是 zip
        if out[:4] != b"PK\x03\x04":
            raise WrongPassword()
    elif ole.has("Workbook") or ole.has("Book"):
        out = _decrypt_xls(ole, password)
    else:
        raise NotSupported("認不出加密方式。")
    with open(out_path, "wb") as f:
        f.write(out)
    return True


# ======================================================================
# 七、自我測試（開發用；對照官方公開測試檔）
# ======================================================================
def self_test(folder):
    import os
    cases = [
        ("example_password.xlsx", "example.xlsx", "Password1234_"),
        ("ecma376agile_sha1_password.xlsx", "example.xlsx", "Password1234_"),
        ("ecma376standard_password.docx", "ecma376standard_password_plain.docx", "Password1234_"),
        ("rc4cryptoapi_password.xls", "rc4cryptoapi_password_plain.xls", "Password1234_"),
    ]
    inp = os.path.join(folder, "inputs")
    outp = os.path.join(folder, "outputs")
    tmp = os.path.join(folder, "_got")
    os.makedirs(tmp, exist_ok=True)
    ok = 0
    for enc, expect, pw in cases:
        got = os.path.join(tmp, enc + ".out")
        try:
            decrypt_file(os.path.join(inp, enc), got, pw)
            a = open(got, "rb").read()
            if expect:
                b = open(os.path.join(outp, expect), "rb").read()
                same = (a == b)  # 和官方正確答案逐位元組比對
                print(("  OK  " if same else "  ✗   ") + enc + ("" if same else "（和答案不同）"))
                ok += 1 if same else 0
            else:
                print("  OK  " + enc)
                ok += 1
        except Exception as e:
            # 密碼錯測試
            print("  ✗   %s -> %s: %s" % (enc, type(e).__name__, e))
    # 錯誤密碼應被擋
    try:
        decrypt_file(os.path.join(inp, "rc4cryptoapi_password.xls"),
                     os.path.join(tmp, "wrong.out"), "0000")
        print("  ✗   錯誤密碼竟然沒被擋")
    except WrongPassword:
        print("  OK  錯誤密碼正確被擋")
        ok += 1
    # 上鎖→解回原檔（不靠外部套件）
    total = len(cases) + 2
    try:
        src = os.path.join(outp, "example.xlsx")
        locked = os.path.join(tmp, "locked.xlsx")
        back = os.path.join(tmp, "back.xlsx")
        encrypt_file(src, locked, "測試密碼Test123")
        decrypt_file(locked, back, "測試密碼Test123")
        same = open(src, "rb").read() == open(back, "rb").read()
        print(("  OK  " if same else "  ✗   ") + "上鎖→解回＝原檔")
        ok += 1 if same else 0
    except Exception as e:
        print("  ✗   上鎖測試：%s: %s" % (type(e).__name__, e))
    print("通過 %d / %d" % (ok, total))
    return ok == total


def _main(argv):
    if len(argv) >= 3 and argv[1] == "--自我測試":
        return 0 if self_test(argv[2]) else 1
    if len(argv) >= 3 and argv[1] == "--檢查":
        print(describe(argv[2]))
        return 0
    if len(argv) < 3:
        print(__doc__)
        return 2
    in_path, out_path = argv[1], argv[2]
    password = None
    lock = False
    i = 3
    while i < len(argv):
        if argv[i] in ("--上鎖", "--加密"):
            lock = True; i += 1
        elif argv[i] == "--密碼" and i + 1 < len(argv):
            password = argv[i + 1]; i += 2
        elif argv[i] == "--config" and i + 1 < len(argv):
            with open(argv[i + 1], "r", encoding="utf-8") as f:
                cfg = json.load(f)
            password = cfg.get("password") or cfg.get("密碼")
            i += 2
        else:
            i += 1
    if not password:
        print("!! 沒拿到密碼。用 --密碼 或 --config config.json（裡面要有 password 欄位）。")
        return 2
    try:
        if lock:
            encrypt_file(in_path, out_path, password)
            print("完成：已上鎖（加密）並寫到 %s" % out_path)
            return 0
        decrypt_file(in_path, out_path, password)
        print("完成：已解密並寫到 %s" % out_path)
        return 0
    except WrongPassword:
        print("!! 密碼不對（或這個檔的鎖和密碼對不上）。檔案沒有被動過。")
        return 3
    except NotSupported as e:
        print("!! 不支援：%s" % e)
        return 4
    except Exception as e:
        print("!! 解密失敗：%s: %s" % (type(e).__name__, e))
        return 5


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
