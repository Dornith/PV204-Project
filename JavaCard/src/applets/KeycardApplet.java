package applets;

import applets.jcmathlib.*;
import applets.jcmathlib.curves.SecP256k1;
import javacard.framework.*;
import javacard.security.*;

import static javacard.framework.ISO7816.OFFSET_P1;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class KeycardApplet extends Applet {

    static final byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
    static final byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
    static final byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

    static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
    static final byte TLV_PUB_KEY = (byte) 0x80;
    static final byte TLV_PRIV_KEY = (byte) 0x81;
    static final byte TLV_CHAIN_CODE = (byte) 0x82;

    static final byte EXPORT_KEY_P1_CURRENT = 0x00;
    static final byte EXPORT_KEY_P1_DERIVE = 0x01;
    static final byte EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT = 0x02;

    static final byte EXPORT_KEY_P2_PRIVATE_AND_PUBLIC = 0x00;
    static final byte EXPORT_KEY_P2_PUBLIC_ONLY = 0x01;
    static final byte EXPORT_KEY_P2_EXTENDED_PUBLIC = 0x02;

    static final byte SIGN_P1_CURRENT_KEY = 0x00;
    static final byte SIGN_P1_DERIVE = 0x01;
    static final byte SIGN_P1_DERIVE_AND_MAKE_CURRENT = 0x02;

    static final byte[] EIP_1581_PREFIX = { (byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D};

    static final byte INS_GENERATE_KEY = (byte) 0xD4;
    static final byte INS_SIGN = (byte) 0xC0;
    static final byte INS_DERIVE_KEY = (byte) 0xD0;
    static final byte INS_SET_SEED = (byte) 0xA0;
    static final byte INS_EXPORT_KEY = (byte) 0x90;


    static final byte MAX_DATA_LENGTH = 127;
    static final byte UID_LENGTH = 16;
    static final short CHAIN_CODE_SIZE = 32;
    static final short KEY_UID_LENGTH = 32;
    static final short BIP39_SEED_SIZE = CHAIN_CODE_SIZE * 2;
    static final byte KEY_PATH_MAX_DEPTH = 10;
    static final byte DERIVE_P1_SOURCE_MASK = (byte) 0xC0;

    private Crypto crypto;
    private ECCurve secp256k1;

    private byte[] derivationOutput;

    private ResourceManager rm;
    private BigNat order;
    private ECPrivateKey masterPrivate;
    private boolean isExtended;
    private byte[] masterChainCode;
    private byte[] altChainCode;
    private byte[] chainCode;
    private ECPublicKey masterPublic;
    private short tmpPathLen;
    private byte[] keyPath;
    private short keyPathLen;
    private byte[] tmpPath;

    private byte[] uid;
    private byte[] keyUID;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new KeycardApplet(bArray, bOffset, bLength);
    }

    public KeycardApplet(byte[] bArray, short bOffset, byte bLength) {
        crypto = new Crypto();
        rm = new ResourceManager((short) 256);
        secp256k1 = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b,
                SecP256k1.G, SecP256k1.r, rm);

        order = new BigNat((short) secp256k1.r.length,
                JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        byte[] oneInHex = new byte[order.length()];
        oneInHex[0] = 0x01;

        uid = new byte[UID_LENGTH];
        derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE), JCSystem.CLEAR_ON_RESET);
        masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
        masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
        isExtended = false;
        masterChainCode = new byte[CHAIN_CODE_SIZE];
        altChainCode = new byte[CHAIN_CODE_SIZE];
        chainCode = masterChainCode;
        resetCurveParameters();
        // Key path related variables
        keyUID = new byte[KEY_UID_LENGTH];
        keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
        tmpPath = JCSystem.makeTransientByteArray((short)(KEY_PATH_MAX_DEPTH * 4), JCSystem.CLEAR_ON_RESET);
        keyPathLen = 0;
        tmpPathLen = 0;
        register();
    }

    /**
     * This method is called on every incoming APDU. This method is just a dispatcher which invokes the correct method
     * depending on the INS of the APDU.
     *
     * @param apdu the JCRE-owned APDU object.
     * @throws ISOException any processing error
     */
    public void process(APDU apdu) throws ISOException {
        apdu.setIncomingAndReceive();
        byte[] apduBuffer = apdu.getBuffer();

        try {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_GENERATE_KEY:
                    generateKey(apdu);
                    break;
                case INS_SIGN:
                    sign(apdu);
                    break;
                case INS_DERIVE_KEY:
                    deriveKey(apdu);
                    break;
                case INS_SET_SEED:
                    setRandomSeed(apdu);
                    break;
                case INS_EXPORT_KEY:
                    exportKey(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;
            }
        } catch(ISOException sw) {
            handleException(apdu, sw.getReason());
        } catch (CryptoException ce) {
            handleException(apdu, (short)(ISO7816.SW_UNKNOWN | ce.getReason()));
        } catch (Exception e) {
            handleException(apdu, ISO7816.SW_UNKNOWN);
        }
    }

    private void handleException(APDU apdu, short sw) {
        byte[] apduBuffer = apdu.getBuffer();
        Util.setShort(apduBuffer, (short) 0, sw);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    private void setRandomSeed(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len = apdu.getIncomingLength();
        if (len != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        crypto.random.setSeed(apduBuffer, ISO7816.OFFSET_CDATA, (short) 64);
    }

    private void generateKeyUIDAndPrepareResponse(byte[] apduBuffer) {
        if (isExtended) {
            crypto.sha256.doFinal(masterChainCode, (short) 0, CHAIN_CODE_SIZE, altChainCode, (short) 0);
        }

        short pubLen = masterPublic.getW(apduBuffer, (short) 0);
        crypto.sha256.doFinal(apduBuffer, (short) 0, pubLen, keyUID, (short) 0);
        Util.arrayCopy(keyUID, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, KEY_UID_LENGTH);
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        boolean makeCurrent = false;
        byte derivationSource = (byte) (apduBuffer[OFFSET_P1] & DERIVE_P1_SOURCE_MASK);

        switch((byte) (apduBuffer[OFFSET_P1] & ~DERIVE_P1_SOURCE_MASK)) {
            case SIGN_P1_CURRENT_KEY:
                derivationSource = DERIVE_P1_SOURCE_CURRENT;
                break;
            case SIGN_P1_DERIVE:
                break;
            case SIGN_P1_DERIVE_AND_MAKE_CURRENT:
                makeCurrent = true;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
        }
        short len = (short) (apdu.getIncomingLength());
        short pathLen = (short) (len - MessageDigest.LENGTH_SHA_256);
        updateDerivationPath(apduBuffer, MessageDigest.LENGTH_SHA_256, pathLen, derivationSource);
        doDerive(apduBuffer, MessageDigest.LENGTH_SHA_256);
        if (len - pathLen != 32) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short msgOffset = ISO7816.OFFSET_CDATA;
        byte[] auxRand = new byte[32];
        crypto.random.generateData(auxRand, (short) 0, (short) 32);

        byte[] signature = new byte[64];

        SchnorrSignature schnorr = new SchnorrSignature(secp256k1, rm);

        schnorr.sign(apduBuffer, msgOffset,
                derivationOutput, (short) 0,
                auxRand, (short) 0, (short) 32,
                signature, (short) 0);
        if (makeCurrent) {
            commitTmpPath();
        }
        Util.arrayCopyNonAtomic(signature, (short) 0, apduBuffer, (short) ISO7816.OFFSET_CDATA, (short) 64);
        apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, (short) 64);
    }

    private void loadSeed(byte[] apduBuffer) {
        if (apduBuffer[ISO7816.OFFSET_LC] != BIP39_SEED_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        crypto.bip32MasterFromSeed(apduBuffer, (short) ISO7816.OFFSET_CDATA, BIP39_SEED_SIZE, apduBuffer, (short) ISO7816.OFFSET_CDATA);

        JCSystem.beginTransaction();
        isExtended = true;

        masterPrivate.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);

        Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), masterChainCode, (short) 0, CHAIN_CODE_SIZE);
        short pubLen = secp256k1.derivePublicKey(masterPrivate, apduBuffer, (short) 0);

        masterPublic.setW(apduBuffer, (short) 0, pubLen);
        resetKeyStatus();
        generateKeyUIDAndPrepareResponse(apduBuffer);
        JCSystem.commitTransaction();
    }

    private void resetKeyStatus() {
        keyPathLen = 0;
    }

    private void deriveKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        updateDerivationPath(apduBuffer, (short) 0, len, apduBuffer[OFFSET_P1]);
        commitTmpPath();
    }

    private void exportKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short dataLen = apdu.getIncomingLength();

        if (!masterPrivate.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        boolean publicOnly;
        boolean extendedPublic;

        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case EXPORT_KEY_P2_PRIVATE_AND_PUBLIC:
                publicOnly = false;
                extendedPublic = false;
                break;
            case EXPORT_KEY_P2_PUBLIC_ONLY:
                publicOnly = true;
                extendedPublic = false;
                break;
            case EXPORT_KEY_P2_EXTENDED_PUBLIC:
                publicOnly = true;
                extendedPublic = true;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return;
        }

        boolean makeCurrent = false;
        byte derivationSource = (byte) (apduBuffer[OFFSET_P1] & DERIVE_P1_SOURCE_MASK);

        switch ((byte) (apduBuffer[OFFSET_P1] & ~DERIVE_P1_SOURCE_MASK)) {
            case EXPORT_KEY_P1_CURRENT:
                derivationSource = DERIVE_P1_SOURCE_CURRENT;
                break;
            case EXPORT_KEY_P1_DERIVE:
                break;
            case EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT:
                makeCurrent = true;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return;
        }

        updateDerivationPath(apduBuffer, (short) 0, dataLen, derivationSource);

        boolean eip1581 = isEIP1581();

        if (!(publicOnly || eip1581) || (extendedPublic && eip1581)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        doDerive(apduBuffer, (short) 0);

        short off = ISO7816.OFFSET_CDATA;

        apduBuffer[off++] = TLV_KEY_TEMPLATE;
        off++;

        short len;

        if (publicOnly) {
            apduBuffer[off++] = TLV_PUB_KEY;
            off++;
            len = secp256k1.derivePublicKey(derivationOutput, (short) 0, apduBuffer, off);
            apduBuffer[(short) (off - 1)] = (byte) len;
            off += len;

            if (extendedPublic) {
                apduBuffer[off++] = TLV_CHAIN_CODE;
                off++;
                Util.arrayCopyNonAtomic(derivationOutput, Crypto.KEY_SECRET_SIZE, apduBuffer, off, CHAIN_CODE_SIZE);
                len = CHAIN_CODE_SIZE;
                apduBuffer[(short) (off - 1)] = (byte) len;
                off += len;
            }
        } else {
            apduBuffer[off++] = TLV_PRIV_KEY;
            off++;

            Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, off, Crypto.KEY_SECRET_SIZE);
            len = Crypto.KEY_SECRET_SIZE;

            apduBuffer[(short) (off - 1)] = (byte) len;
            off += len;
        }

        len = (short) (off - ISO7816.OFFSET_CDATA);
        apduBuffer[(ISO7816.OFFSET_CDATA + 1)] = (byte) (len - 2);

        if (makeCurrent) {
            commitTmpPath();
        }

        apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, len);
    }

    /**
     * Updates the derivation path for a subsequent EXPORT KEY/SIGN APDU. Optionally stores the result in the current path.
     *
     * @param path the path
     * @param off the offset in the path
     * @param len the len of the path
     * @param source derivation source
     */
    private void updateDerivationPath(byte[] path, short off, short len, byte source) {
        if (!isExtended) {
            if (len == 0) {
                tmpPathLen = 0;
            } else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            return;
        }

        short newPathLen;
        short pathLenOff;

        byte[] srcKeyPath = keyPath;

        switch (source) {
            case DERIVE_P1_SOURCE_MASTER:
                newPathLen = len;
                pathLenOff = 0;
                break;
            case DERIVE_P1_SOURCE_PARENT:
                if (keyPathLen < 4) {
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                newPathLen = (short) (keyPathLen + len - 4);
                pathLenOff = (short) (keyPathLen - 4);
                break;
            case DERIVE_P1_SOURCE_CURRENT:
                newPathLen = (short) (keyPathLen + len);
                pathLenOff = keyPathLen;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return;
        }

        if (((short) (len % 4) != 0) || (newPathLen > keyPath.length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short pathOff = (short) (ISO7816.OFFSET_CDATA + off);

        Util.arrayCopyNonAtomic(srcKeyPath, (short) 0, tmpPath, (short) 0, pathLenOff);
        Util.arrayCopyNonAtomic(path, pathOff, tmpPath, pathLenOff, len);
        tmpPathLen = newPathLen;
    }

    void commitTmpPath() {
        JCSystem.beginTransaction();
        Util.arrayCopy(tmpPath, (short) 0, keyPath, (short) 0, tmpPathLen);
        keyPathLen = tmpPathLen;
        JCSystem.commitTransaction();
    }

    private void doDerive(byte[] apduBuffer, short off) {
        if (tmpPathLen == 0) {
            masterPrivate.getS(derivationOutput, (short) 0);
            return;
        }

        short scratchOff = (short) (ISO7816.OFFSET_CDATA + off);
        short dataOff = (short) (scratchOff + Crypto.KEY_DERIVATION_SCRATCH_SIZE);

        short pubKeyOff = (short) (dataOff + masterPrivate.getS(apduBuffer, dataOff));
        pubKeyOff = Util.arrayCopyNonAtomic(chainCode, (short) 0, apduBuffer, pubKeyOff, CHAIN_CODE_SIZE);

        if (!crypto.bip32IsHardened(tmpPath, (short) 0)) {
            masterPublic.getW(apduBuffer, pubKeyOff);
        } else {
            apduBuffer[pubKeyOff] = 0;
        }

        for (short i = 0; i < tmpPathLen; i += 4) {
            if (i > 0) {
                Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, dataOff, (short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE));

                if (!crypto.bip32IsHardened(tmpPath, i)) {
                    secp256k1.derivePublicKey(apduBuffer, dataOff, apduBuffer, pubKeyOff);
                } else {
                    apduBuffer[pubKeyOff] = 0;
                }
            }

            if (!crypto.bip32CKDPriv(tmpPath, i, apduBuffer, scratchOff, apduBuffer, dataOff, derivationOutput, (short) 0)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }
    }

    private void generateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        apduBuffer[ISO7816.OFFSET_LC] = BIP39_SEED_SIZE;
        crypto.random.generateData(apduBuffer, ISO7816.OFFSET_CDATA, BIP39_SEED_SIZE);

        loadSeed(apduBuffer);
    }

    private void resetCurveParameters() {
        SECP256k1.setCurveParameters(masterPublic);
        SECP256k1.setCurveParameters(masterPrivate);
    }

    private boolean isEIP1581() {
        boolean hasMinimumLength = tmpPathLen >= (short)(((short) EIP_1581_PREFIX.length) + 8);
        boolean prefixMatches = Util.arrayCompare(EIP_1581_PREFIX, (short) 0, tmpPath, (short) 0,
                (short) EIP_1581_PREFIX.length) == 0;

        if (!hasMinimumLength) {
            // Path too short - expected 20+ bytes, got fewer
            return false;
        }

        if (!prefixMatches) {
            // Prefix doesn't match EIP-1581 standard
            return false;
        }

        return true;
    }

}