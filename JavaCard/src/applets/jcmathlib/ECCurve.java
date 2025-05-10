package applets.jcmathlib;

import applets.SECP256k1;
import javacard.framework.JCSystem;
import javacard.security.*;

import static applets.SECP256k1.*;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECCurve {
    static final byte SECP256K1_FP[] = {
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    static final byte SECP256K1_A[] = {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    };
    static final byte SECP256K1_B[] = {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
    };
    static final byte SECP256K1_G[] = {
            (byte)0x04,
            (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
            (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
            (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
            (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
            (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
            (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
            (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
            (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    public static final byte SECP256K1_R[] = {
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
            (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
            (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    static final byte SECP256K1_K = (byte)0x01;

    static final short SECP256K1_KEY_SIZE = 256;
    public final short KEY_BIT_LENGTH, POINT_SIZE, COORD_SIZE;
    public ResourceManager rm;

    public byte[] p, a, b, G, r;
    public BigNat pBN, aBN, bBN, rBN;


    public KeyPair disposablePair;
    public ECPrivateKey disposablePriv;
    public ECPublicKey disposablePub;

    private KeyAgreement ecPointMultiplier;

    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

    /**
     * Creates new curve object from provided parameters. Parameters are not copied, the
     * arrays must not be changed.
     *
     * @param p array with p
     * @param a array with a
     * @param b array with b
     * @param G array with base point G
     * @param r array with r
     */
    public ECCurve(byte[] p, byte[] a, byte[] b, byte[] G, byte[] r, ResourceManager rm) {
        KEY_BIT_LENGTH = (short) (p.length * 8);
        POINT_SIZE = (short) G.length;
        COORD_SIZE = (short) ((short) (G.length - 1) / 2);

        this.p = p;
        this.a = a;
        this.b = b;
        this.G = G;
        this.r = r;
        this.rm = rm;

        pBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        pBN.fromByteArray(p, (short) 0, (short) p.length);
        aBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        aBN.fromByteArray(a, (short) 0, (short) a.length);
        bBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        bBN.fromByteArray(b, (short) 0, (short) b.length);
        rBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        rBN.fromByteArray(r, (short) 0, (short) r.length);

        disposablePair = newKeyPair(null);
        disposablePriv = (ECPrivateKey) disposablePair.getPrivate();
        disposablePub = (ECPublicKey) disposablePair.getPublic();
        ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    }

    /**
     * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
     */
    public void updateAfterReset() {
        pBN.fromByteArray(p, (short) 0, (short) p.length);
        aBN.fromByteArray(a, (short) 0, (short) a.length);
        bBN.fromByteArray(b, (short) 0, (short) b.length);
        rBN.fromByteArray(r, (short) 0, (short) r.length);
    }



    /**
     * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
     * @param keyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
     * @return new or existing object with fresh key pair value
     */
    public KeyPair newKeyPair(KeyPair keyPair) {
        ECPublicKey pubKey;
        ECPrivateKey privKey;
        if (keyPair == null) {
            pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_BIT_LENGTH, false);
            privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_BIT_LENGTH, false);
            keyPair = new KeyPair(pubKey, privKey);
        } else {
            pubKey = (ECPublicKey) keyPair.getPublic();
            privKey = (ECPrivateKey) keyPair.getPrivate();
        }

        privKey.setFieldFP(p, (short) 0, (short) p.length);
        privKey.setA(a, (short) 0, (short) a.length);
        privKey.setB(b, (short) 0, (short) b.length);
        privKey.setG(G, (short) 0, (short) G.length);
        privKey.setR(r, (short) 0, (short) r.length);
        privKey.setK((short) 1);

        pubKey.setFieldFP(p, (short) 0, (short) p.length);
        pubKey.setA(a, (short) 0, (short) a.length);
        pubKey.setB(b, (short) 0, (short) b.length);
        pubKey.setG(G, (short) 0, (short) G.length);
        pubKey.setR(r, (short) 0, (short) r.length);
        pubKey.setK((short) 1);

        keyPair.genKeyPair();

        return keyPair;
    }

    /**
     * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
     * the private key by the G point of the curve.
     *
     * @param privateKey the private key
     * @param pubOut the output buffer for the public key
     * @param pubOff the offset in pubOut
     * @return the length of the public key
     */
    public short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
        return multiplyPoint(privateKey, this.G, (short) 0, (short) this.G.length, pubOut, pubOff);
    }


    /**
     * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
     * the private key by the G point of the curve.
     *
     * @param privateKey the private key
     * @param pubOut the output buffer for the public key
     * @param pubOff the offset in pubOut
     * @return the length of the public key
     */
    public short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
        disposablePriv.setS(privateKey, privOff, (short)(SECP256K1_KEY_SIZE/8));
        return derivePublicKey(disposablePriv, pubOut, pubOff);
    }

    /**
     * Multiplies a scalar in the form of a private key by the given point. Internally uses a special version of EC-DH
     * supported since JavaCard 3.0.5 which outputs both X and Y in their uncompressed form.
     *
     * @param privateKey the scalar in a private key object
     * @param point the point to multiply
     * @param pointOff the offset of the point
     * @param pointLen the length of the point
     * @param out the output buffer
     * @param outOff the offset in the output buffer
     * @return the length of the data written in the out buffer
     */
    short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out, short outOff) {
        ecPointMultiplier.init(privateKey);
        return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
    }

    static void setCurveParameters(ECKey key) {
        key.setA(SECP256K1_A, (short) 0x00, (short) SECP256K1_A.length);
        key.setB(SECP256K1_B, (short) 0x00, (short) SECP256K1_B.length);
        key.setFieldFP(SECP256K1_FP, (short) 0x00, (short) SECP256K1_FP.length);
        key.setG(SECP256K1_G, (short) 0x00, (short) SECP256K1_G.length);
        key.setR(SECP256K1_R, (short) 0x00, (short) SECP256K1_R.length);
        key.setK(SECP256K1_K);
    }
}