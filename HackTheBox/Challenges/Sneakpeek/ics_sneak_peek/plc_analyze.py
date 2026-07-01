# Paste the full block 0 hex here
block0_hex = "c57bb7fac4efdd00d49a796326f9c3f45200ebc6ae734537003222c84877e97e95e92900260120033a2a007ed600dacd26e329f9dacfc10300f8eff87e0077961611a44346003ad2cafe4d4ddef400e3d315336da9007aa3c4004c121fcbba91f900e300de885672b500a76200124f80b3ebc9745c00e9474dc0d700237311006ee8e339fae4800f690056d941ee7da610920405006caa11930011a161002c412601f24d119f60fc00978306a0008b6e33008aa4373100c256335600ce00fad03b4cdd62ed00d37b31001f9a8a9e59fdea003a5da93ea2008d0900b191015c61006643dd008c4e29b73d0cd8005e32140061b665b1875800bcc400bc6d7f745618ab6fa300e65075001428f18790236f0d6d6200351bdc044989b800610039ac4febcaaa7700a6f200f0a158f9c17ad48800156c005b875aec0422e20060854be19a00b60072004d4a81a113ad00e700897fa0d297a800028cde2b597d4600a9cbd48eb1cd024b6c00d1a0415e004900c505e61b5f00a547cd00c200770ddb006c007a4e7b370c007113c966fe4eef430024aad5d49559b300afaa22a369f9245788ff00418f96cd3f5300bd84c32e00398242194b071900bb1da48f8d007770b591b70563002f0bfa009b9a9990a2a5ce80d6f600df1f846400d5677e44e0af0200037c95c0726a6489ee0900ec138300c900b624f7b50076001a4e68a6e45cedb643002d50cff21b0055b1a87c6c0551fa00204930579f36b9ad818100a0835a567c33fd5d00ed226ed415e9b263e3002290db00893cfd00f2582ceb08ec0011a9a2f940b36a68008a48d46bbb535baf13ce00895aa7ad1d82d9a100a1e9a22ee100e09214b2a5006a85db012ce43e0044a5a12932e97ce70018c300b0ed26109a2c9cf725c000d55ae4540831a000dadc25e94500e5f14100c7c304f407996900a0484298aa9b44baa7e300cabffe468da7babd38f00034e658619d860057baee005500dd8a2009ad9902006c24839cd84a6d534c001d00b50d924e287598442c82000fffa2122a471500d533058cf915ba00820034d3ff009feb7fce97e2755f002e760004705704e3f30081c900a62f332b00eb28aad9e21d230076b0007cfc137aea40a100755e8f3ce5710d1108001358b4511bc1793a2300ff50e80061c6beb0936c0e569600e6dc1e14d2df1cd7af00f93100e381559c68fd0047d51914b30f2ba100867dcd83141be922d2c2006897ec93ceaf32a61a10001cea62f75400bde28e8821c63ce100d9254e223139000d17cf3aea58ddbf0098cc004453bf7a00a0c3310092ab81d1655effaf00c37c8a3519005ecd15a766cd3c85b9e4000400bf1d9075b5ee003f00422bfd1ffe35001ef6d141b47b00d47157834b64af5c00b2e6c5f4bc1edc0ba40044f2075b001f960005e15e004db0c1002700"

data = bytes.fromhex(block0_hex)

print(f"Block 0 length: {len(data)} bytes")
print()

# Strategy 1: Extract only non-zero bytes (strip null separators)
non_zero = bytes(b for b in data if b != 0x00)
print(f"[*] Non-zero bytes ({len(non_zero)} bytes):")
print(f"    Hex: {non_zero.hex()}")
print()

# Strategy 2: Check if data is stored as 2-byte big-endian words (value, 0x00)
# i.e., every even byte is data, every odd byte is 0x00
even_bytes = bytes(data[i] for i in range(0, len(data), 2))
odd_bytes  = bytes(data[i] for i in range(1, len(data), 2))
print(f"[*] Even-indexed bytes (if 2-byte word encoding):")
print(f"    Hex: {even_bytes.hex()}")
print(f"[*] Odd-indexed bytes:")
print(f"    Hex: {odd_bytes.hex()}")
print()

# Strategy 3: Find all 16-byte windows with high entropy (no repeated bytes)
import collections
print("[*] High-entropy 16-byte windows (candidate MD5 hashes):")
for i in range(len(data) - 15):
    window = data[i:i+16]
    unique = len(set(window))
    zeroes = window.count(0x00)
    if unique >= 12 and zeroes == 0:
        print(f"    offset {i:4d}: {window.hex()}")

# Strategy 4: Look for the pattern in block 2's tail
# Block 2 ended at some point before FF fill - find where data ends
print()
print("[*] Checking where block 2 data ends (from earlier dump):")
block2_hex = "a262560fa66800ffffffffffffffff"  # from earlier
# The transition point tells us total data size

# Strategy 5: Try reading with address=0, length=16 to see if server
# returns the hash directly when asking for just the start
print()
print("[*] Null-byte positions (first 64 bytes):")
for i, b in enumerate(data[:64]):
    print(f"  [{i:3d}] 0x{b:02x} {'<-- NULL' if b == 0 else ''}")
