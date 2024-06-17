def feistel_encrypt(block, key, rounds=16):
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    subkeys = [(key >> (i * 8)) & 0xFF for i in range(rounds)]

    for i in range(rounds):
        new_L = R
        new_R = L ^ F(R, subkeys[i])
        L, R = new_L, new_R

    return (L << 32) | R


def F(R, K):
    temp = (R ^ K)
    temp = (temp + K) % 0xFFFFFFFF
    return ((temp << 1) & 0xFFFFFFFF) | (temp >> 31)


def text_to_blocks(text):
    text_bytes = text.encode('utf-8')
    while len(text_bytes) % 8 != 0:
        text_bytes += b'\0'
    blocks = []
    for i in range(0, len(text_bytes), 8):
        block = int.from_bytes(text_bytes[i:i + 8], byteorder='big')
        blocks.append(block)
    return blocks


def blocks_to_text(blocks):
    text_bytes = b''.join(block.to_bytes(8, byteorder='big') for block in blocks)
    return text_bytes.decode('utf-8').rstrip('\0')


plaintext = "دو صد گفته چون نيم كردار نيست"

blocks = text_to_blocks(plaintext)

key = 0x0F1E2D3C4B5A69780F1E2D3C4B5A6978

encrypted_blocks = [feistel_encrypt(block, key) for block in blocks]

encrypted_text = ''.join(f"{block:016X}" for block in encrypted_blocks)
print(f"Encrypted: {encrypted_text}")


def feistel_decrypt(block, key, rounds=16):
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    subkeys = [(key >> (i * 8)) & 0xFF for i in range(rounds)]

    for i in range(rounds - 1, -1, -1):
        new_R = L
        new_L = R ^ F(L, subkeys[i])
        L, R = new_L, new_R

    return (L << 32) | R


decrypted_blocks = [feistel_decrypt(block, key) for block in encrypted_blocks]

decrypted_text = blocks_to_text(decrypted_blocks)
print(f"Decrypted: {decrypted_text}")