package com.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.net.*;
import java.util.*;
import java.io.*;

public class network_analyser {
    private static final int TIMEOUT = 1000; // Timeout en millisecondes
    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;

    // Scan des ports sur une adresse IP donnée avec détection de service
    public void scanPorts(String host, int startPort, int endPort) {
        System.out.println("\n--- Scan de ports sur " + host + " ---");
        for (int port = startPort; port <= endPort; port++) {
            String status = "FERMÉ";
            String banner = "";
            String proto = detectProtocol(port, port);
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(host, port), TIMEOUT);
                status = "OUVERT";
                // Tentative de récupération de bannière (service)
                socket.setSoTimeout(500);
                try {
                    InputStream in = socket.getInputStream();
                    byte[] buf = new byte[256];
                    int len = in.read(buf);
                    if (len > 0) {
                        banner = new String(buf, 0, len).replaceAll("\r|\n", " ").trim();
                    }
                } catch (IOException ignored) {}
                socket.close();
            } catch (IOException e) {
                // Port fermé ou non accessible
            }
            // Afficher le protocole pour tous les ports, ouvert ou fermé
            System.out.printf("Port %5d : %-6s | Protocole : %-15s%s\n", port, status, (proto != null ? proto : "Inconnu"), (status.equals("OUVERT") && !banner.isEmpty()) ? " | Bannière : " + banner : "");
        }
    }

    // Capture de paquets avec Pcap4J
    public void capturePackets(String interfaceName, int packetCount) {
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
            if (nif == null) {
                System.out.println("Interface non trouvée: " + interfaceName);
                return;
            }
            int snapLen = 65536;
            int timeout = 10;
            PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            System.out.println("\n--- Capture de paquets sur " + interfaceName + " ---");
            for (int i = 0; i < packetCount; i++) {
                Packet packet = handle.getNextPacketEx();
                byte[] data = packet.getRawData();
                int length = data.length;
                System.out.println("\n==============================");
                System.out.println("Paquet #" + (i + 1));
                System.out.println("Horodatage : " + handle.getTimestamp());
                System.out.println("Taille : " + length + " octets");
                // Ethernet
                if (packet.contains(org.pcap4j.packet.EthernetPacket.class)) {
                    org.pcap4j.packet.EthernetPacket eth = packet.get(org.pcap4j.packet.EthernetPacket.class);
                    System.out.println("[Ethernet]");
                    System.out.println("  Source MAC : " + eth.getHeader().getSrcAddr());
                    System.out.println("  Destination MAC : " + eth.getHeader().getDstAddr());
                }
                // IP
                if (packet.contains(org.pcap4j.packet.IpV4Packet.class)) {
                    org.pcap4j.packet.IpV4Packet ip = packet.get(org.pcap4j.packet.IpV4Packet.class);
                    System.out.println("[IPv4]");
                    System.out.println("  Source IP : " + ip.getHeader().getSrcAddr());
                    System.out.println("  Destination IP : " + ip.getHeader().getDstAddr());
                    System.out.println("  Protocole : " + ip.getHeader().getProtocol());
                }
                // TCP
                if (packet.contains(org.pcap4j.packet.TcpPacket.class)) {
                    org.pcap4j.packet.TcpPacket tcp = packet.get(org.pcap4j.packet.TcpPacket.class);
                    System.out.println("[TCP]");
                    int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                    int dstPort = tcp.getHeader().getDstPort().valueAsInt();
                    String proto = detectProtocol(srcPort, dstPort);
                    System.out.println("  Port source : " + srcPort + " | Port destination : " + dstPort + " | Protocole applicatif : " + (proto != null ? proto : "Inconnu"));
                    // Détection HTTP par payload (complément)
                    if ((srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080 || srcPort == 443 || dstPort == 443) && data.length > 4) {
                        String payload = new String(data);
                        if (payload.startsWith("GET") || payload.startsWith("POST") || payload.startsWith("HTTP") || payload.startsWith("PUT") || payload.startsWith("DELETE") || payload.startsWith("HEAD")) {
                            System.out.println("  Protocole applicatif : HTTP (payload)");
                        }
                    }
                }
                // UDP
                if (packet.contains(org.pcap4j.packet.UdpPacket.class)) {
                    org.pcap4j.packet.UdpPacket udp = packet.get(org.pcap4j.packet.UdpPacket.class);
                    System.out.println("[UDP]");
                    int srcPort = udp.getHeader().getSrcPort().valueAsInt();
                    int dstPort = udp.getHeader().getDstPort().valueAsInt();
                    String proto = detectProtocol(srcPort, dstPort);
                    System.out.println("  Port source : " + srcPort + " | Port destination : " + dstPort + " | Protocole applicatif : " + (proto != null ? proto : "Inconnu"));
                }
                // Affichage hexadécimal + ASCII façon Wireshark
                System.out.println("[Données brutes]");
                for (int offset = 0; offset < data.length; offset += 16) {
                    StringBuilder hex = new StringBuilder();
                    StringBuilder ascii = new StringBuilder();
                    for (int j = 0; j < 16 && (offset + j) < data.length; j++) {
                        byte b = data[offset + j];
                        hex.append(String.format("%02X ", b));
                        ascii.append((b >= 32 && b <= 126) ? (char) b : '.');
                    }
                    System.out.printf("%04X  %-48s  %s\n", offset, hex.toString(), ascii.toString());
                }
            }
            handle.close();
        } catch (Exception e) {
            System.err.println("Erreur lors de la capture : " + e.getMessage());
        }
    }

    // Obtenir les informations des interfaces réseau
    public void listNetworkInterfaces() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            System.out.println("\n--- Interfaces réseau détectées ---");
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isLoopback() && ni.isUp()) {
                    System.out.println("Interface : " + ni.getName());
                    System.out.println("  Nom affiché : " + ni.getDisplayName());
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();
                        System.out.println("  Adresse : " + addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("Erreur lors de la liste des interfaces : " + e.getMessage());
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

    // Détection de protocole applicatif par port enrichie
    private String detectProtocol(int srcPort, int dstPort) {
        int port = srcPort;
        if (isKnownPort(dstPort)) port = dstPort;
        switch (port) {
            case 80: return "HTTP";
            case 443: return "HTTPS";
            case 53: return "DNS";
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 20: return "FTP-DATA";
            case 123: return "NTP";
            case 161: return "SNMP";
            case 162: return "SNMP Trap";
            case 389: return "LDAP";
            case 67: case 68: return "DHCP";
            case 69: return "TFTP";
            case 445: return "SMB";
            case 3306: return "MySQL";
            case 5432: return "PostgreSQL";
            case 5900: return "VNC";
            case 3389: return "RDP";
            case 5060: return "SIP";
            case 8080: return "HTTP-alt";
            case 135: return "MS RPC";
            case 139: return "NetBIOS";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 1723: return "PPTP";
            case 1521: return "Oracle DB";
            case 2049: return "NFS";
            case 6000: return "X11";
            case 8000: return "HTTP-alt";
            case 8888: return "HTTP-alt";
            default: return null;
        }
    }
    private boolean isKnownPort(int port) {
        int[] known = {80,443,53,21,22,23,25,110,143,20,123,161,162,389,67,68,69,445,3306,5432,5900,3389,5060,8080,135,139,993,995,1723,1521,2049,6000,8000,8888};
        for (int p : known) if (port == p) return true;
        return false;
    }

    // Main pour tester l'analyseur
    public static void main(String[] args) {
        network_analyser analyzer = new network_analyser();
        // Lister les interfaces réseau
        System.out.println("=== Network Interfaces ===");
        analyzer.listNetworkInterfaces();
        // Scanner les ports
        System.out.println("\n=== Port Scan ===");
        analyzer.scanPorts("localhost", 1, 1000);
        // Capturer des paquets
        System.out.println("\n=== Packet Capture ===");
        analyzer.capturePackets("wlp2s0", 5);
    }
}