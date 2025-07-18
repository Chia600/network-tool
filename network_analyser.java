import java.net.*;
import java.util.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class network_analyser {
    private static final int TIMEOUT = 1000; // Timeout en millisecondes
    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;

    // Scan des ports sur une adresse IP donnée
    public void scanPorts(String host, int startPort, int endPort) {
        System.out.println("Scanning ports on " + host + "...");
        
        for (int port = startPort; port <= endPort; port++) {
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(host, port), TIMEOUT);
                System.out.println("Port " + port + " is open");
                socket.close();
            } catch (IOException e) {
                // Port fermé ou non accessible
            }
        }
    }

    // Capture simple de paquets UDP
    public void capturePackets(String interfaceName, int port, int packetCount) {
        try {
            DatagramChannel channel = DatagramChannel.open();
            channel.socket().bind(new InetSocketAddress(port));
            
            ByteBuffer buffer = ByteBuffer.allocate(65536);
            
            System.out.println("Capturing " + packetCount + " packets on port " + port + "...");
            
            for (int i = 0; i < packetCount; i++) {
                buffer.clear();
                SocketAddress source = channel.receive(buffer);
                buffer.flip();
                
                byte[] data = new byte[buffer.remaining()];
                buffer.get(data);
                
                System.out.println("Packet " + (i + 1) + " from " + source);
                System.out.println("Data length: " + data.length + " bytes");
                System.out.println("Data: " + bytesToHex(data));
            }
            
            channel.close();
        } catch (IOException e) {
            System.err.println("Error capturing packets: " + e.getMessage());
        }
    }

    // Obtenir les informations des interfaces réseau
    public void listNetworkInterfaces() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isLoopback() && ni.isUp()) {
                    System.out.println("\nInterface: " + ni.getName());
                    System.out.println("Display name: " + ni.getDisplayName());
                    
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();
                        System.out.println("Address: " + addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("Error listing interfaces: " + e.getMessage());
        }
    }

    // Conversion des bytes en hexadécimal
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    // Main pour tester l'analyseur
    public static void main(String[] args) {
        network_analyser analyzer = new network_analyser();
        
        // Lister les interfaces réseau
        System.out.println("=== Network Interfaces ===");
        analyzer.listNetworkInterfaces();
        
        // Scanner les ports
        System.out.println("\n=== Port Scan ===");
        analyzer.scanPorts("localhost", 1, 100);
        
        // Capturer des paquets
        System.out.println("\n=== Packet Capture ===");
        analyzer.capturePackets("eth0", 12345, 5);
    }
}