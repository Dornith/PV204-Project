package host;

import applets.KeycardApplet;
import cardtools.RunConfig;
import cardtools.CardManager;
import com.licel.jcardsim.remote.JavaCardRemoteClient;
import com.licel.jcardsim.utils.JavaCardApiProcessor;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.SecureRandom;

public class TestSignCommand {

    private static final byte[] APPLET_AID_BYTES = {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
            (byte) 0x06
    };
    private static final byte CLA_BYTE = (byte) 0xB0;
    static final byte INS_GENERATE_KEY = (byte) 0xD4;
    static final byte INS_SIGN = (byte) 0xC0;
    static final byte INS_SET_SEED = (byte) 0xA0;
    static final byte INS_EXPORT_KEY = (byte) 0x90;

    private static final byte P1 = (byte) 0x00;
    private static final byte P2 = (byte) 0x00;


    public static byte[] generateSeed() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[64];
        secureRandom.nextBytes(seed);
        return seed;
    }


    public static void main(String[] args) throws Exception {
        CardManager cardManager = new CardManager(true, APPLET_AID_BYTES);

        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setAppletToSimulate(KeycardApplet.class);
        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        System.out.print("Connecting to card simulator...");
        if (!cardManager.Connect(runConfig)) {
            throw new Exception("Connection failed.");
        }
        System.out.println("Connected.");
        //seedRandom(cardManager);
        generateKey(cardManager);
        //signMessage(cardManager);
        exportKey(cardManager);

        System.out.println("Test completed successfully!");
    }
    private static void exportKey(CardManager cardManager) throws CardException {
        System.out.print("Exporting key... ");
        byte[] mainIdentityPath = {
                (byte) 0x80, 0x00, 0x00, 0x2B, // 43' (Purpose - non-wallet usage)
                (byte) 0x80, 0x00, 0x00, 0x3C, // 60' (Coin type - Ethereum)
                (byte) 0x80, 0x00, 0x06, 0x2D, // 1581' (EIP number)
                (byte) 0x80, 0x00, 0x06, 0x2D, // 1581' (test random hardened)
                0x00, 0x00, 0x00, 0x00          // 0 (First identity)
        };
        CommandAPDU exportKeyCmd = new CommandAPDU(CLA_BYTE, INS_EXPORT_KEY, 0x02, 0x02, mainIdentityPath);
        ResponseAPDU response = cardManager.transmit(exportKeyCmd);

        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            return;
        }
        byte[] exportedKey = response.getData();
        System.out.println("Success. Raw exported data: " + bytesToHex(exportedKey));

        // Parse the TLV structure
        parseTLVData(exportedKey);
    }

    private static void parseTLVData(byte[] tlvData) {
        if (tlvData[0] != (byte)0xA1) { // TLV_KEY_TEMPLATE (1 byte)
            System.out.println("Invalid TLV format - missing KEY_TEMPLATE tag");
            return;
        }

        int offset = 2; // Skip the outer tag and length

        while (offset < tlvData.length) {
            byte tag = tlvData[offset++];
            byte length = tlvData[offset++];

            switch (tag) {
                case (byte)0x80: // TLV_PUB_KEY (1 byte tag + 1 byte length)
                    byte[] publicKey = new byte[length];
                    System.arraycopy(tlvData, offset, publicKey, 0, length);
                    System.out.println("Public Key (" + length + " bytes): " + bytesToHex(publicKey));
                    byte prefix = publicKey[0];
                    byte[] xCoord = new byte[32];
                    byte[] yCoord = new byte[32];
                    System.arraycopy(publicKey, 1, xCoord, 0, 32);
                    System.arraycopy(publicKey, 33, yCoord, 0, 32);

                    System.out.println("  Prefix: " + String.format("%02X", prefix));
                    System.out.println("  X Coordinate: " + bytesToHex(xCoord));
                    System.out.println("  Y Coordinate: " + bytesToHex(yCoord));
                    break;

                case (byte)0x81: // TLV_PRIV_KEY (1 byte tag + 1 byte length)
                    byte[] privateKey = new byte[length];
                    System.arraycopy(tlvData, offset, privateKey, 0, length);
                    System.out.println("Private Key (" + length + " bytes): " + bytesToHex(privateKey));
                    break;

                case (byte)0x82: // TLV_CHAIN_CODE (1 byte tag + 1 byte length)
                    byte[] chainCode = new byte[length];
                    System.arraycopy(tlvData, offset, chainCode, 0, length);
                    System.out.println("Chain Code (" + length + " bytes): " + bytesToHex(chainCode));
                    break;

                default:
                    System.out.println("Unknown tag: " + String.format("%02X", tag));
            }

            offset += length;
        }
    }

    private static void seedRandom(CardManager cardManager) throws CardException {
        System.out.print("Seeding random... ");
        byte[] seed = generateSeed();
        CommandAPDU seedCmd = new CommandAPDU(CLA_BYTE, INS_SET_SEED, P1, P2, seed);
        ResponseAPDU response = cardManager.transmit(seedCmd);

        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            return;
        }

        System.out.println("Success. Seeded random.");
    }

    private static void generateKey(CardManager cardManager) throws CardException {
        System.out.print("Generating key... ");
        CommandAPDU generateKeyCmd = new CommandAPDU(CLA_BYTE, INS_GENERATE_KEY, P1, P2);
        ResponseAPDU response = cardManager.transmit(generateKeyCmd);

        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            return;
        }

        byte[] publicKey = response.getData();
        System.out.println("Success. Public key generated: " + bytesToHex(publicKey));
    }
    private static byte[] signMessage(CardManager cardManager) throws Exception {
        System.out.print("Signing message... ");
        byte [] message = new byte[32];
        String hexString = "bb2dce3524d27eaf309951ed87f77e3937a8b3d33d1f4651fa12101c876d208e";
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
        }
        byte[] mainIdentityPath = {
                (byte) 0x80, 0x00, 0x00, 0x2B, // 43' (Purpose - non-wallet usage)
                (byte) 0x80, 0x00, 0x00, 0x3C, // 60' (Coin type - Ethereum)
                (byte) 0x80, 0x00, 0x06, 0x2D, // 1581' (EIP number)
                (byte) 0x80, 0x00, 0x06, 0x2D, // 1581' (test random hardened)
                0x00, 0x00, 0x00, 0x00          // 0 (First identity)
        };
        byte[] data = new byte[message.length + mainIdentityPath.length];
        System.arraycopy(message, 0, data, 0, message.length);

        System.arraycopy(mainIdentityPath, 0, data, message.length, mainIdentityPath.length);

        CommandAPDU signCmd = new CommandAPDU(CLA_BYTE, INS_SIGN, 0x02, P2, data);
        ResponseAPDU response = cardManager.transmit(signCmd);
        
        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            throw new Exception("Signing failed");
        }
        
        byte[] signature = response.getData();
        System.out.println("Success. Signature received: " + signature.length + " bytes");
        return signature;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}