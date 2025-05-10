package applets.jcmathlib;

import applets.SECP256k1;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Implementation of Schnorr signatures for JavaCard using the secp256k1 curve
 * according to BIP0340 specification.
 */
public class SchnorrSignature {
    // Status word constants
    private static final short SW_INVALID_MESSAGE_LENGTH = (short) 0x6A80;
    private static final short SW_INVALID_SECRET_KEY = (short) 0x6A81;
    private static final short SW_VERIFICATION_FAILED = (short) 0x6A82;
    private static final short SW_SIGNATURE_FAILED = (short) 0x6A83;

    // Buffer sizes and constants
    private static final short MESSAGE_LENGTH = 32;
    private static final short SIGNATURE_LENGTH = 64;
    private static final short POINT_LENGTH = 32; // x-only public key
    private static final short PRIVATEKEY_LENGTH = 32;

    // Tag strings for the tagged hash function
    private static final byte[] TAG_AUX = {
            'B', 'I', 'P', '0', '3', '4', '0', '/', 'a', 'u', 'x'
    };

    private static final byte[] TAG_NONCE = {
            'B', 'I', 'P', '0', '3', '4', '0', '/', 'n', 'o', 'n', 'c', 'e'
    };

    private static final byte[] TAG_CHALLENGE = {
            'B', 'I', 'P', '0', '3', '4', '0', '/', 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e'
    };

    // Resources
    private MessageDigest sha256;
    private ECCurve secp256k1;
    private ResourceManager rm;

    // Temporary buffers
    private byte[] tmpBuffer;
    private byte[] hashBuffer;
    private byte[] nonceBuffer;
    private byte[] pointBuffer;
    private byte[] combBytes = new byte[96];

    /**
     * Constructor for SchnorrSignature
     *
     * @param secp256k1 the SECP256k1 curve utilities
     * @param rm        the ResourceManager for BigNat operations
     */
    public SchnorrSignature(ECCurve secp256k1, ResourceManager rm) {
        this.secp256k1 = secp256k1;
        this.rm = rm;
        this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Allocate buffers
        this.tmpBuffer = new byte[256]; // Larger buffer for various operations
        this.hashBuffer = new byte[32];
        this.nonceBuffer = new byte[32];
        this.pointBuffer = new byte[65];
        this.combBytes = new byte[96];// Uncompressed point format
    }

    /**
     * Generate a tagged hash as defined in BIP0340
     *
     * @param tag       the tag to use
     * @param msg       the message to hash
     * @param msgOffset offset in the message buffer
     * @param msgLength the length of the message
     * @param out       output buffer for the hash
     * @param outOffset offset in the output buffer
     * @return the length of the hash
     */
    private short taggedHash(byte[] tag, byte[] msg, short msgOffset, short msgLength, byte[] out, short outOffset) {
        // Hash the tag
        sha256.reset();
        sha256.doFinal(tag, (short) 0, (short) tag.length, hashBuffer, (short) 0);

        // Create buffer with tag hash twice + message
        short offset = 0;
        Util.arrayCopyNonAtomic(hashBuffer, (short) 0, tmpBuffer, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(hashBuffer, (short) 0, tmpBuffer, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(msg, msgOffset, tmpBuffer, offset, msgLength);

        // Hash the whole thing
        sha256.reset();
        return sha256.doFinal(tmpBuffer, (short) 0, (short) (64 + msgLength), out, outOffset);
    }

    /**
     * XOR operation between two byte arrays
     *
     * @param a         first array
     * @param aOffset   offset in first array
     * @param b         second array
     * @param bOffset   offset in second array
     * @param length    length to XOR
     * @param out       output buffer
     * @param outOffset offset in output buffer
     */
    private void xor(byte[] a, short aOffset, byte[] b, short bOffset, short length, byte[] out, short outOffset) {
        for (short i = 0; i < length; i++) {
            out[(short) (outOffset + i)] = (byte) (a[(short) (aOffset + i)] ^ b[(short) (bOffset + i)]);
        }
    }

    /**
     * Check if a point has an even Y coordinate
     *
     * @param point       the point to check (full uncompressed point)
     * @param pointOffset offset in the point buffer
     * @return true if the Y coordinate is even
     */
    private boolean hasEvenY(byte[] point, short pointOffset) {
        // For uncompressed points (0x04 || x || y), check if y is even
        // Y coordinate starts at offset 33 (after 0x04 prefix and 32-byte X)
        // Just check the last bit of the last byte of Y
        return (point[(short) (pointOffset + 64)] & 1) == 0;
    }

    /**
     * Convert a BigNat to a byte array with proper padding to 32 bytes
     *
     * @param bn        the BigNat to convert
     * @param out       output buffer
     * @param outOffset offset in output buffer
     * @return number of bytes written
     */
    private short bigNatToBytes(BigNat bn, byte[] out, short outOffset) {
        short len = bn.copyToByteArray(out, outOffset);

        // If the length is less than 32 bytes, pad with leading zeros
        if (len < 32) {
            Util.arrayCopyNonAtomic(out, outOffset, out, (short) (outOffset + (32 - len)), len);
            Util.arrayFillNonAtomic(out, outOffset, (short) (32 - len), (byte) 0);
            return 32;
        }
        return len;
    }

    /**
     * Create a BigNat from a byte array
     *
     * @param data   source byte array
     * @param offset offset in source array
     * @param length length of data
     * @param out    BigNat to store the result
     */
    private void bytesToBigNat(byte[] data, short offset, short length, BigNat out) {
        out.fromByteArray(data, offset, length);
    }

    /**
     * Sign a message using Schnorr signature as defined in BIP0340
     *
     * @param msg             the message to sign (must be 32 bytes)
     * @param msgOffset       offset in the message buffer
     * @param secKey          the private key
     * @param secKeyOffset    offset in the private key buffer
     * @param auxRand         auxiliary random data for nonce generation
     * @param auxRandOffset   offset in the auxRand buffer
     * @param auxRandLength   length of auxRand
     * @param signature       output buffer for the signature
     * @param signatureOffset offset in the signature buffer
     * @return the length of the signature
     */
    public short sign(byte[] msg, short msgOffset,
                      byte[] secKey, short secKeyOffset,
                      byte[] auxRand, short auxRandOffset, short auxRandLength,
                      byte[] signature, short signatureOffset) {

        // Check message length
        if ((short) (msgOffset + MESSAGE_LENGTH) > msg.length) {
            ISOException.throwIt(SW_INVALID_MESSAGE_LENGTH);
        }

        // Create BigNat for private key using direct construction
        BigNat secKeyBN = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bytesToBigNat(secKey, secKeyOffset, PRIVATEKEY_LENGTH, secKeyBN);

        // Create BigNat for secp256k1 order n
        BigNat secp256k1OrderN = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bytesToBigNat(SECP256k1.SECP256K1_R, (short) 0, (short) 32, secp256k1OrderN);

        // Check if 1 <= secKey <= n-1
        BigNat one = new BigNat((short) 1, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        one.setValue((byte) 1);

        BigNat nMinusOne = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        nMinusOne.copy(secp256k1OrderN);
        nMinusOne.decrement();

        if (secKeyBN.isLesser(one) || nMinusOne.isLesser(secKeyBN)) {
            // Instead of freeing BigNats, simply throw because cleanup is handled by the resource allocator
            ISOException.throwIt(SW_INVALID_SECRET_KEY);
        }

        // Derive public key point P
        secp256k1.derivePublicKey(secKey, secKeyOffset, pointBuffer, (short) 0);

        // Check if P has even Y, negate secKey if needed
        if (!hasEvenY(pointBuffer, (short) 0)) {
            // Negate secKey: n - secKey
            BigNat newSecKey = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
            newSecKey.copy(secp256k1OrderN);
            newSecKey.subtract(secKeyBN);

            // Replace secKeyBN with negated value
            secKeyBN.copy(newSecKey);
        }

        // Get x-coordinate of P (32 bytes after the 0x04 prefix)
        byte[] pubKeyX = new byte[32];
        Util.arrayCopyNonAtomic(pointBuffer, (short) 1, pubKeyX, (short) 0, (short) 32);

        // Compute tagged hash of auxiliary random data
        taggedHash(TAG_AUX, auxRand, auxRandOffset, auxRandLength, hashBuffer, (short) 0);

        // Convert secKey to bytes for XOR operation
        bigNatToBytes(secKeyBN, tmpBuffer, (short) 0);

        // XOR secKey with tagged hash of aux to generate nonce seed
        xor(tmpBuffer, (short) 0, hashBuffer, (short) 0, (short) 32, nonceBuffer, (short) 0);

        // Compute t = bytes(nonce seed) || bytes(P) || msg
        short offset = 0;
        Util.arrayCopyNonAtomic(nonceBuffer, (short) 0, combBytes, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(pubKeyX, (short) 0, combBytes, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(msg, msgOffset, combBytes, offset, MESSAGE_LENGTH);
        offset += MESSAGE_LENGTH;

        taggedHash(TAG_NONCE, combBytes, (short) 0, offset, hashBuffer, (short) 0);

        BigNat k0 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bytesToBigNat(hashBuffer, (short) 0, (short) 32, k0);
        k0.mod(secp256k1OrderN);

        // Check if k0 is 0
        if (k0.isZero()) {
            ISOException.throwIt(SW_SIGNATURE_FAILED);
        }

        // Convert k0 to byte array for EC point multiplication
        bigNatToBytes(k0, tmpBuffer, (short) 0);

        // Compute R = k0 * G
        secp256k1.derivePublicKey(tmpBuffer, (short) 0, pointBuffer, (short) 0);

        // Check if R has even Y, negate k if needed
        BigNat k = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        k.copy(k0);

        if (!hasEvenY(pointBuffer, (short) 0)) {
            // Negate k: n - k0
            k.zero();
            k.copy(secp256k1OrderN);
            k.subtract(k0);
        }
        // k0 is not explicitly freed

        // Get x-coordinate of R (32 bytes after the 0x04 prefix)
        byte[] rx = new byte[32];
        Util.arrayCopyNonAtomic(pointBuffer, (short) 1, rx, (short) 0, (short) 32);

        // Compute e = int(tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)) mod n
        offset = 0;
        Util.arrayCopyNonAtomic(rx, (short) 0, combBytes, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(pubKeyX, (short) 0, combBytes, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(msg, msgOffset, combBytes, offset, MESSAGE_LENGTH);
        offset += MESSAGE_LENGTH;

        taggedHash(TAG_CHALLENGE, combBytes, (short) 0, offset, hashBuffer, (short) 0);

        BigNat e = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bytesToBigNat(hashBuffer, (short) 0, (short) 32, e);
        e.mod(secp256k1OrderN);

        // Compute s = (k + e * secKey) mod n
        BigNat s = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        // Compute e * secKey mod n
        e.modMult(secKeyBN, secp256k1OrderN);

        // Compute (k + e * secKey) mod n
        s.copy(k);
        s.modAdd(e, secp256k1OrderN);

        // Create 64-byte signature (R.x || s)
        Util.arrayCopyNonAtomic(rx, (short) 0, signature, signatureOffset, (short) 32);
        bigNatToBytes(s, signature, (short) (signatureOffset + 32));

        return SIGNATURE_LENGTH;
    }
}
