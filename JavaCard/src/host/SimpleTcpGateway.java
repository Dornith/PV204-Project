package host;

import applets.KeycardApplet;
import cardtools.RunConfig;
import cardtools.SimulatedCardChannelLocal;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import com.licel.jcardsim.utils.AIDUtil;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;

public class SimpleTcpGateway {
    public static void main(String[] args) throws Exception {
        // Create simulator
        byte[] appletId = {
                (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
                (byte) 0x06
        };
        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setAppletToSimulate(KeycardApplet.class);
        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        AID appletAID = new AID(appletId, (short) 0, (byte) appletId.length);

        AID appletAIDRes = simulator.installApplet(appletAID, KeycardApplet.class, runConfig.getInstallData(), (short) 0, (byte) runConfig.getInstallData().length);
        simulator.selectApplet(appletAID);

        // Start server
        try (ServerSocket serverSocket = new ServerSocket(9025)) {
            System.out.println("TCP gateway listening on port 9025...");
            while (true) {
                try (
                        Socket client = serverSocket.accept();
                        DataInputStream in = new DataInputStream(client.getInputStream());
                        DataOutputStream out = new DataOutputStream(client.getOutputStream())
                ) {
                    System.out.println("[INFO] New client connected: " + client.getRemoteSocketAddress());

                    int len = in.readUnsignedShort();
                    byte[] apdu = new byte[len];
                    in.readFully(apdu);
                    System.out.println("[DEBUG] ← APDU recv: " + bytesToHex(apdu));

                    byte[] response = simulator.transmitCommand(apdu);
                    System.out.println("[DEBUG] → Response: " + bytesToHex(response));

                    out.writeShort(response.length);
                    out.write(response);
                    out.flush();
                } catch (Exception e) {
                    System.err.println("[ERROR] During client I/O: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}