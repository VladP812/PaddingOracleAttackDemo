def split_into_blocks(bytess: bytes, block_size: int = 4):
    return [bytess[i:i+block_size] for i in range(0, len(bytess), block_size)]

def apply_padding(bytess: bytes, block_size: int = 4):
    """PCKS#7 Style padding"""
    rem = len(bytess) % block_size
    pad_len = block_size - rem if rem != 0 else block_size
    return bytess + bytes([pad_len]) * pad_len

def remove_padding(bytess: bytes, block_size: int = 4) -> bytes:
    if not bytess or len(bytess) % block_size != 0:
        raise ValueError("Invalid padded input length")
    pad_len = bytess[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding byte")
    if bytess[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return bytess[:-pad_len]

# Toy block cypher: XOR-block 
# INSECURE; only for demonstration - but it doesn't matter since the attack is not 
# about how secure the encryption is, it would still work even with the most secure encryption
def toy_block_encrypt(block: bytes, key_block: bytes) -> bytes:
    """XOR each byte with corresponding key byte (key_block repeats/truncates)."""
    return bytes(b ^ key_block[i % len(key_block)] for i, b in enumerate(block))

def toy_block_decrypt(block: bytes, key_block: bytes) -> bytes:
    # XOR is symmetric so decryption = encryption
    return toy_block_encrypt(block, key_block)

# CBC-style encryption using the toy block cypher
def encrypt_cbc(plaintext: bytes, key_block: bytes, iv: bytes, block_size: int = 4) -> bytes:
    print(f"Plaintext: {plaintext}")
    padded = apply_padding(plaintext, block_size)
    print(f"Padded message: {padded}")
    blocks = split_into_blocks(padded, block_size)
    print(f"Blocks: {blocks}")
    prev = iv
    cyphertext = b""
    for blk in blocks:
        xored = bytes(a ^ b for a, b in zip(blk, prev))
        ct = toy_block_encrypt(xored, key_block)
        cyphertext += ct
        prev = ct
    return cyphertext

def decrypt_cbc(cyphertext: bytes, key_block: bytes, iv: bytes, block_size: int = 4) -> bytes:
    if len(cyphertext) % block_size != 0:
        raise ValueError("Invalid cyphertext length")
    blocks = split_into_blocks(cyphertext, block_size)
    prev = iv
    plaintext_padded = b""
    for ct in blocks:
        xored = toy_block_decrypt(ct, key_block)
        pt_blk = bytes(a ^ b for a, b in zip(xored, prev))
        plaintext_padded += pt_blk
        prev = ct
    return remove_padding(plaintext_padded, block_size)

def padding_oracle(cyphertext: bytes, key_block: bytes, iv: bytes, block_size: int = 4) -> bool:
    """
    Simulates a server that decrypts and checks padding.
    Returns True if padding is valid, False otherwise.
    !!!!!!!!!!!!!!!!!!This is exactly what the attacker utilizes!!!!!!!!!!!!!!!
    """
    try:
        if len(cyphertext) % block_size != 0:
            return False
        cyphertext_blocks = split_into_blocks(cyphertext, block_size)
        prev = iv
        plaintext_padded = b""
        for cyphertext_block in cyphertext_blocks:
            decrypted = toy_block_decrypt(cyphertext_block, key_block)
            # after the decryption it's still not original plaintext, 
            # we still need to xor it with the previous cyphertext block! 
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted, prev))
            plaintext_padded += plaintext_block
            prev = cyphertext_block
        # Checks if padding is valid
        # Throws error if invalid, so this oracle returns False
        remove_padding(plaintext_padded, block_size)
        return True
    except ValueError:
        return False


def run_padding_oracle_attack(cyphertext: bytes, iv: bytes, block_size: int = 4):
    """
    Demonstrates a padding oracle attack.
    The attacker knows: cyphertext, iv, block_size, DOESN'T KNOW THE KEY!!!!
    The attacker can query: padding_oracle (which uses the secret key internally)
    The attacker wants: the plaintext
    """
    print("\n" + "="*60)
    print("PADDING ORACLE ATTACK DEMONSTRATION, KEY IS NOT KNOWN!!!")
    print("="*60)
    
    # Split cyphertext into blocks
    cyphertext_blocks = split_into_blocks(cyphertext, block_size)
    print(f"\ncyphertext blocks: {cyphertext_blocks}")
    print(f"Number of blocks: {len(cyphertext_blocks)}")
    
    # We'll decrypt each block by manipulating the previous block (or IV)
    # For simplicity, we'll decrypt the first block
    recovered_plaintext = b""
    
    # Prepend IV to all blocks so we can treat all blocks uniformly
    all_blocks = [iv] + cyphertext_blocks
    
    # Beginning from the last block
    for block_number in range(len(cyphertext_blocks), 0, -1):
        print(f"\n--- Decrypting block {block_number - 1} ---")
        
        # We manipulate the previous block to decrypt the current block
        previous_cyphertext_block = bytearray(all_blocks[block_number])
        current_cyphertext_block = all_blocks[block_number - 1]
        
        # Recovered intermediate state - after block cypher decryption, before XORing with the previous cyphertext block
        # This is one of if not the most important piece of data!
        # Since we only change the preceeding block, keeping the next one intact, the intermediate value will remain the same
        intermediate = bytearray(block_size)
        
        # Attack from right to left, last byte to first byte of the current block we're cracking
        for pos in range(block_size - 1, -1, -1):
            print(f"  Attacking byte position {pos}...")
            # We want padding to be: (block_size - pos)
            # e.g., if pos=3 (last byte), we want padding 0x01
            #       if pos=2, we want padding 0x02 0x02, etc.
            target_padding = block_size - pos
            
            # Prepare the modified previous block, bytearray() makes a copy so we don't change the original prev
            modified_prev = bytearray(previous_cyphertext_block)
            # Set already-known bytes to produce correct padding
            for known_pos in range(pos + 1, block_size):
                modified_prev[known_pos] = intermediate[known_pos] ^ target_padding
            
            # Try all 256 possible values for the current byte
            found = False
            for guess in range(256):
                modified_prev[pos] = guess
                
                # Create test cyphertext: the rest of the previous blocks + modified_prev + current block
                test_cyphertext = bytes(modified_prev) + bytes(current_cyphertext_block)
                if block_number < len(cyphertext_blocks) - 1:
                    # Add remaining blocks to make valid cyphertext
                    test_cyphertext = b"".join(cyphertext_blocks[:block_number] + [test_cyphertext])
                
                # Query the oracle
                if padding_oracle(test_cyphertext, key, iv, block_size):
                    # Valid padding! We found the right value
                    # The intermediate byte is: guess XOR target_padding
                    intermediate[pos] = guess ^ target_padding
                    
                    # The plaintext byte is: intermediate XOR original_prev_block
                    plaintext_byte = intermediate[pos] ^ previous_cyphertext_block[pos]
                    
                    print(f"    Found! guess={guess:02x}, intermediate={intermediate[pos]:02x}, plaintext_byte={plaintext_byte:02x} ('{chr(plaintext_byte) if 32 <= plaintext_byte < 127 else '?'}')")
                    found = True
                    break
            
            if not found:
                print(f"    Warning: Could not find valid padding for position {pos}")
        
        # Recover the plaintext for this block
        block_plaintext = bytes(intermediate[i] ^ previous_cyphertext_block[i] for i in range(block_size))
        recovered_plaintext = block_plaintext + recovered_plaintext
        print(f"  Block plaintext (with padding): {block_plaintext}")
    
    # Remove padding from final result
    try:
        final_plaintext = remove_padding(recovered_plaintext, block_size)
        print(f"\n{'='*60}")
        print(f"RECOVERED PLAINTEXT: {final_plaintext}")
        print(f"As string: {final_plaintext.decode('utf-8', errors='replace')}")
        print(f"{'='*60}\n")
        return final_plaintext
    except ValueError:
        print(f"\nRecovered bytes (with padding): {recovered_plaintext}")
        print(f"Note: Padding removal failed, showing raw bytes")
        return recovered_plaintext


if __name__ == "__main__":
    msg = "HELLO WORLD".encode()
    key = "KEY".encode()
    iv = "rand".encode()
    block_size = 4
    if len(iv) != block_size:
        raise Exception("The size of IV has to be the same as the block size")
    cyphertext = encrypt_cbc(msg, key, iv, block_size)
    print(f"Cyphertext: {cyphertext}")
    decrypted = decrypt_cbc(cyphertext, key, iv, block_size)
    print(f"Decrypted WITH KEY: {decrypted}")
    cracked_msg = run_padding_oracle_attack(cyphertext, iv, block_size)
