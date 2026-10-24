#!/usr/bin/env python3
"""Experimental conversion to the legacy SINF layout observed on this Mac.

Uses a genuine matching account credential. Does not decrypt app binaries.
Preserves all ten named rights and content-key material. Removes the extra
eight-byte rights suffix in the new record and restores legacy date fields.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from zipfile import BadZipFile, ZipFile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def atoms(data: bytes | bytearray, start: int, end: int):
    offset = start
    while offset < end:
        if offset + 8 > end:
            raise ValueError("truncated atom header")
        size, tag = struct.unpack_from(">I4s", data, offset)
        if size < 8 or size > end - offset:
            raise ValueError(f"invalid atom size at {offset:#x}")
        yield tag, offset + 8, offset + size
        offset += size


def unique(fields, tag):
    found = [(start, end) for name, start, end in fields if name == tag]
    if len(found) != 1:
        raise ValueError(f"expected exactly one {tag!r} atom")
    return found[0]


def rights_value(data: bytes | bytearray, bounds, tag: bytes):
    start, end = bounds
    # Rights dictionaries may end in an opaque trailer. Keep it verbatim.
    found = [i + 4 for i in range(start, end - 7, 8) if data[i:i + 4] == tag]
    if len(found) != 1:
        raise ValueError(f"expected exactly one {tag!r} right")
    return found[0]


def atom(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I4s", len(data) + 8, tag) + data


def crypt_private(data: bytes, credential: bytes, name: bytes, iviv: bytes,
                  *, encrypt: bool) -> bytes:
    """Encrypt or decrypt one AES-CBC private-record payload."""
    key = bytes(value ^ 0x30 for value in credential)
    iv = hashlib.md5(name.split(b"\0", 1)[0] + iviv).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    operation = cipher.encryptor() if encrypt else cipher.decryptor()
    return operation.update(data) + operation.finalize()


def verify_converted_sinf(sinf: bytes, credential: bytes) -> None:
    """Check the rebuilt rights and the legacy private-record round trip."""
    root = list(atoms(sinf, 0, len(sinf)))
    if len(root) != 1 or root[0][0] != b"sinf":
        raise ValueError("expected one outer sinf atom")
    schi = unique(list(atoms(sinf, root[0][1], root[0][2])), b"schi")
    fields = list(atoms(sinf, *schi))
    visible_rights = sinf[slice(*unique(fields, b"righ"))]
    name = sinf[slice(*unique(fields, b"name"))]
    iviv = sinf[slice(*unique(fields, b"iviv"))]
    private = sinf[slice(*unique(fields, b"priv"))]
    if len(iviv) != 16 or len(private) != 440 or private[-8:] != bytes(8):
        raise ValueError("invalid converted private-record layout")
    clear = crypt_private(private[:-8], credential, name, iviv, encrypt=False) + private[-8:]
    if clear[:4] != b"itun" or clear[20:24] != b"key " or clear[44:48] != b"iviv":
        raise ValueError("converted private record did not decode")
    private_fields = list(atoms(clear, 16, len(clear)))
    if clear[slice(*unique(private_fields, b"righ"))] != visible_rights:
        raise ValueError("converted visible and private rights differ")
    if crypt_private(clear[:-8], credential, name, iviv, encrypt=True) != private[:-8]:
        raise ValueError("converted private record did not round trip")


def normalize(sinf, credential):
    """Validate one new-format SINF, then rebuild it in the observed legacy layout."""
    original = sinf
    # 1. Parse the outer record and require the exact layout we know how to convert.
    if len(credential) != 16:
        raise ValueError("credential must contain exactly 16 bytes")
    root = list(atoms(sinf, 0, len(sinf)))
    if len(root) != 1 or root[0][0] != b"sinf":
        raise ValueError("expected one outer sinf atom")
    outer = list(atoms(sinf, root[0][1], root[0][2]))
    fields = list(atoms(sinf, *unique(outer, b"schi")))
    values = {t: sinf[s:e] for t, s, e in fields}
    if len(values) != len(fields):
        raise ValueError("duplicate scheme field")
    rights = values[b"righ"]
    expected = [b"veID", b"plat", b"aver", b"tran", b"sing",
                b"song", b"tool", b"medi", b"mode", b"hi32"]
    if len(rights) != 88 or [rights[i:i + 4] for i in range(0, 80, 8)] != expected:
        raise ValueError("not the observed ten-rights plus eight-byte-suffix layout")
    if values.keys() != {b"user", b"key ", b"iviv", b"righ", b"name", b"priv"}:
        raise ValueError("unexpected scheme fields for this conversion")
    if len(values[b"priv"]) != 448:
        raise ValueError("expected fully encrypted 448-byte private record")
    # 2. Decode the private record and confirm its rights match the visible ones.
    clear = crypt_private(values[b"priv"], credential, values[b"name"],
                          values[b"iviv"], encrypt=False)
    if clear[:4] != b"itun" or clear[20:24] != b"key " or clear[44:48] != b"iviv":
        raise ValueError("credential does not decode this private record")
    private_fields = list(atoms(clear, 16, len(clear)))
    if [t for t, _, _ in private_fields] != [b"key ", b"iviv", b"tmpr", b"righ", b"name"]:
        raise ValueError("unexpected private record fields")
    private_rights = unique(private_fields, b"righ")
    if clear[slice(*private_rights)] != rights:
        raise ValueError("private rights mismatch")
    if crypt_private(clear, credential, values[b"name"],
                     values[b"iviv"], encrypt=True) != values[b"priv"]:
        raise ValueError("original private record does not round trip exactly")
    # 3. Clear mode and remove the eight-byte suffix from both rights copies.
    mode_at = rights_value(rights, (0, len(rights)), b"mode")
    original_mode = struct.unpack_from(">I", rights, mode_at)[0]
    normalized_rights = bytearray(rights[:80])
    struct.pack_into(">I", normalized_rights, mode_at, 0)
    normalized_rights = bytes(normalized_rights)
    # 4. Rebuild the private record with the legacy encryption boundary.
    normalized_clear = clear[:16] + b"".join(
        atom(t, normalized_rights if t == b"righ" else clear[s:e])
        for t, s, e in private_fields
    )
    if len(normalized_clear) != 440 or normalized_clear[-8:] != bytes(8):
        raise ValueError("legacy record must end with eight zero name bytes")
    private = (crypt_private(normalized_clear[:-8], credential, values[b"name"],
                             values[b"iviv"], encrypt=True) + normalized_clear[-8:])
    # 5. Add the legacy date fields and reserialize the enclosing atoms.
    # Match the scalar date representation observed in three installed,
    # same-account legacy mode-zero licenses. Do not invent new dates.
    tran_at = rights_value(rights, (0, len(rights)), b"tran")
    values[b"crdt"] = rights[tran_at:tran_at + 4]
    values[b"asdt"] = bytes(4)
    values[b"righ"] = normalized_rights
    values[b"priv"] = private
    order = [b"user", b"crdt", b"asdt", b"key ", b"iviv", b"righ", b"name", b"priv"]
    scheme = b"".join(atom(t, values[t]) for t in order)
    result = atom(b"sinf", b"".join(
        atom(t, scheme if t == b"schi" else sinf[s:e]) for t, s, e in outer
    ))
    # 6. Verify the final record and preservation of private key material.
    verify_converted_sinf(result, credential)
    # Private key, IV, tmpr, name, and version header remain byte-identical.
    rebuilt = list(atoms(normalized_clear, 16, len(normalized_clear)))
    for tag in (b"key ", b"iviv", b"tmpr", b"name"):
        if clear[slice(*unique(private_fields, tag))] != normalized_clear[slice(*unique(rebuilt, tag))]:
            raise ValueError("private key material or metadata changed unexpectedly")
    report = {"credential_verified": True, "exact_original_roundtrip": True,
              "private_bytes": len(clear),
              "changes": {"mode": {"from": original_mode, "to": 0}},
              "conversion": "experimental legacy layout",
              "input_bytes": len(original), "output_bytes": len(result),
              "encrypted_private_bytes": 432, "unencrypted_zero_trailer_bytes": 8,
              "named_rights_preserved": 10, "extra_rights_suffix_removed_bytes": 8,
              "date_fields": "crdt copied from existing tran; asdt zero",
              "private_key_iv_tmpr_name_preserved": True,
              "outer_sign_preserved": True}
    return result, report


def convert(ipa: Path, output: Path, credential_path: Path):
    if output.resolve() in (ipa.resolve(), credential_path.resolve()):
        raise ValueError("output must differ from input and credential")
    if output.exists() and (output.samefile(ipa) or output.samefile(credential_path)):
        raise ValueError("output must differ from input and credential")
    credential = credential_path.read_bytes()
    if len(credential) != 16:
        raise ValueError("credential must contain exactly 16 bytes")
    records, replacements = [], {}
    with ZipFile(ipa) as src:
        if len(src.namelist()) != len(set(src.namelist())):
            raise ValueError("duplicate ZIP names")
        for name in src.namelist():
            if "/SC_Info/" in name and name.endswith(".sinf"):
                replacements[name], report = normalize(src.read(name), credential)
                records.append({"path": name, **report})
        if not records:
            raise ValueError("no SINF records found")
        fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp",
                                              dir=output.parent)
        temporary = Path(temporary_name)
        os.close(fd)
        try:
            with ZipFile(temporary, "w") as dst:
                for entry in src.infolist():
                    dst.writestr(entry, replacements.get(entry.filename, src.read(entry)))
            os.replace(temporary, output)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"input": str(ipa), "output": str(output), "records": records}


def main():
    parser = argparse.ArgumentParser(
        description="Convert supported App Store IPA SINF records for macOS launch.",
        epilog=("Example:\n  macosfairfree -i ~/Downloads/app.ipa "
                "-c ~/private/credential.bin\n"
                "  macosfairfree -c ~/private/credential.bin "
                "-o ~/Desktop/app-macos.ipa -i ~/Downloads/app.ipa"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("-i", "--input", type=Path, metavar="IPA", required=True,
                        help="App Store IPA to convert")
    parser.add_argument("-o", "--output", type=Path, metavar="IPA",
                        help="output IPA (default: INPUT-macos.ipa beside input; overwrites existing file)")
    parser.add_argument("-c", "--credential", type=Path, metavar="FILE", required=True,
                        help="matching 16-byte account credential")
    args = parser.parse_args()
    output = args.output or args.input.with_name(f"{args.input.stem}-macos.ipa")
    try:
        report = convert(args.input, output, args.credential)
    except (OSError, ValueError, BadZipFile, KeyError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))
    print(f"SINF data patched successfully; IPA written to: {output}")


if __name__ == "__main__":
    main()
