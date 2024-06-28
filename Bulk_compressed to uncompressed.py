import ecdsa
import binascii

def decompress_pubkey(compressed_pubkey):
    """
    Decompresses a compressed public key.
    """
    prefix = compressed_pubkey[:2]
    x = int(compressed_pubkey[2:], 16)
    curve = ecdsa.SECP256k1.curve
    p = curve.p()
    
    if prefix == '02':
        y_parity = 0
    elif prefix == '03':
        y_parity = 1
    else:
        raise ValueError("Invalid compressed public key prefix")

    y_square = (pow(x, 3, p) + 7) % p
    y = pow(y_square, (p + 1) // 4, p)
    
    if y % 2 != y_parity:
        y = p - y
    
    uncompressed_pubkey = '04' + format(x, '064x') + format(y, '064x')
    return uncompressed_pubkey

def process_keys(input_file, output_file):
    """
    Processes the input file containing compressed public keys and writes the
    uncompressed public keys to the output file.
    """
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            line = line.strip()
            if '#' in line:
                line = line.split('#')[0].strip()
            try:
                uncompressed_pubkey = decompress_pubkey(line)
                outfile.write(uncompressed_pubkey + '\n')
            except ValueError as e:
                print(f"Skipping invalid compressed public key {line}: {e}")

# Replace 'compressed_keys.txt' with your input file name and 'uncompressed_keys.txt' with your desired output file name
input_file = 'compressed_keys.txt.txt'
output_file = 'uncompressed_keys.txt'
process_keys(input_file, output_file)
