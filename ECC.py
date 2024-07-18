from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_signature(private_key, plaintext):
    """
    Generates a digital signature for the given plaintext using the provided private key.

    :param private_key: The ECC private key in PEM format.
    :param plaintext: The plaintext message to be signed.
    :return: The digital signature.
    """
    ECC_private_key = ECC.import_key(private_key)
    sha256_hash = SHA256.new(plaintext)
    signer = DSS.new(ECC_private_key, 'fips-186-3')
    digital_signature = signer.sign(sha256_hash)
    return digital_signature

def verify_signature(public_key, plaintext, digital_signature):
    """
    Verifies the digital signature of the given plaintext using the provided public key.

    :param public_key: The ECC public key in PEM format.
    :param plaintext: The plaintext message that was signed.
    :param digital_signature: The digital signature to be verified.
    :return: Message indicating whether the signature is valid or invalid.
    """
    ECC_public_key = ECC.import_key(public_key)
    verification_sha256_hash = SHA256.new(plaintext)
    verifier = DSS.new(ECC_public_key, 'fips-186-3')
    try:
        verifier.verify(verification_sha256_hash, digital_signature)
        return "\nSignature is valid!"
    except ValueError:
        return "\nSignature is invalid!"

# Main script
if __name__ == "__main__":
    plaintext = input("Enter your secret message: ").encode()

    # Generate ECC key pair
    ECC_key = ECC.generate(curve='P-256')
    private_key = ECC_key.export_key(format='PEM')
    public_key = ECC_key.public_key().export_key(format='PEM')

    # Generate digital signature
    digital_signature = generate_signature(private_key, plaintext)

    # Print keys and signature
    print("\nPrivate key:\n", private_key)
    print("\nPublic key:\n", public_key)
    print("\nDigital signature:\n", digital_signature.hex())

    # Verify the digital signature
    verification_result = verify_signature(public_key, plaintext, digital_signature)
    print(verification_result)


