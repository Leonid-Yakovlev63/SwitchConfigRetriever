import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class SwitchConfigRetriever extends JFrame {
    private JButton startButton;
    private JTextArea statusTextArea;

    public SwitchConfigRetriever() {
        super("Switch Config Retriever");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 300);
        setLocationRelativeTo(null);

        startButton = new JButton("Start");
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                startButton.setEnabled(false);
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        retrieveSwitchConfigs();
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                startButton.setEnabled(true);
                            }
                        });
                    }
                }).start();
            }
        });

        statusTextArea = new JTextArea();
        statusTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusTextArea);

        setLayout(new BorderLayout());
        add(startButton, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void retrieveSwitchConfigs() {
        String saveDirectory = "C:\\SwitchConfigs";
        String subnet = "192.168.200";
        int startIP = 1;
        int endIP = 254;
        String communityString = "public";
        Snmp snmp;
        try {
            snmp = new Snmp(new DefaultUdpTransportMapping());
            snmp.listen();
        } catch (IOException e) {
            updateStatus("Failed to initialize SNMP agent: " + e.getMessage());
            return;
        }
        createManufacturerDirectories(saveDirectory);
        for (int i = startIP; i <= endIP; i++) {
            String ipAddress = subnet + "." + i;
            updateStatus("Scanning switch: " + ipAddress);
            try {
                Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/161");
                CommunityTarget target = new CommunityTarget();
                target.setAddress(targetAddress);
                target.setCommunity(new OctetString(communityString));
                target.setVersion(SnmpConstants.version2c);
                PDU sysInfoPDU = new PDU();
                sysInfoPDU.add(new VariableBinding(new OID("1.3.6.1.2.1.1.2.0")));
                sysInfoPDU.setType(PDU.GET);
                ResponseEvent sysInfoResponseEvent = snmp.send(sysInfoPDU, target);
                PDU sysInfoResponsePDU = sysInfoResponseEvent.getResponse();
                if (sysInfoResponsePDU != null && sysInfoResponsePDU.getErrorStatus() == PDU.noError) {
                    String manufacturer = sysInfoResponsePDU.get(0).getVariable().toString();
                    String configOID = getConfigOID(manufacturer);
                    if (configOID != null) {
                        String manufacturerDirectory = getManufacturerDirectory(saveDirectory, manufacturer);
                        PDU configPDU = new PDU();
                        configPDU.add(new VariableBinding(new OID(configOID)));
                        configPDU.setType(PDU.GET);
                        ResponseEvent configResponseEvent = snmp.send(configPDU, target);
                        PDU configResponsePDU = configResponseEvent.getResponse();
                        if (configResponsePDU != null && configResponsePDU.getErrorStatus() == PDU.noError) {
                            String config = configResponsePDU.get(0).getVariable().toString();
                            String filename = "config_" + ipAddress + ".txt";
                            File file = new File(manufacturerDirectory, filename);
                            try (FileOutputStream fos = new FileOutputStream(file)) {
                                fos.write(config.getBytes());
                                updateStatus("Config saved for switch: " + ipAddress);
                            } catch (IOException e) {
                                updateStatus("Failed to save config for switch: " + ipAddress + " - " + e.getMessage());
                            }
                        } else {
                            // Попытка использовать общий OID
                            String generalConfigOID = "1.3.6.1.2.1.25.3.5.1.4";
                            PDU generalConfigPDU = new PDU();
                            generalConfigPDU.add(new VariableBinding(new OID(generalConfigOID)));
                            generalConfigPDU.setType(PDU.GET);
                            ResponseEvent generalConfigResponseEvent = snmp.send(generalConfigPDU, target);
                            PDU generalConfigResponsePDU = generalConfigResponseEvent.getResponse();
                            if (generalConfigResponsePDU != null && generalConfigResponsePDU.getErrorStatus() == PDU.noError) {
                                String config = generalConfigResponsePDU.get(0).getVariable().toString();
                                String filename = "config_" + ipAddress + ".txt";
                                File file = new File(manufacturerDirectory, filename);
                                try (FileOutputStream fos = new FileOutputStream(file)) {
                                    fos.write(config.getBytes());
                                    updateStatus("Config saved for switch: " + ipAddress);
                                } catch (IOException ex) {
                                    updateStatus("Failed to save config for switch: " + ipAddress + " - " + ex.getMessage());
                                }
                            } else {
                                updateStatus("Failed to retrieve config for switch: " + ipAddress);
                            }
                        }
                    } else {
                        updateStatus("Unsupported switch manufacturer: " + manufacturer);
                    }
                } else {
                    updateStatus("Failed to retrieve sysObjectID for switch: " + ipAddress);
                }
            } catch (IOException e) {
                updateStatus("Error occurred during SNMP operation: " + e.getMessage());
            }
        }
    }


    private void createManufacturerDirectories(String saveDirectory) {
        String[] manufacturers = { "Cisco", "Juniper", "CustomVendor", "d-link" };
        for (String manufacturer : manufacturers) {
            String manufacturerDirectory = getManufacturerDirectory(saveDirectory, manufacturer);
            File directory = new File(manufacturerDirectory);
            if (!directory.exists()) {
                boolean created = directory.mkdirs();
                if (created) {
                    updateStatus("Created directory: " + manufacturerDirectory);
                } else {
                    updateStatus("Failed to create directory: " + manufacturerDirectory);
                }
            }
        }
    }

    private String getManufacturerDirectory(String saveDirectory, String manufacturer) {
        return saveDirectory + File.separator + manufacturer;
    }

    private String getConfigOID(String manufacturer) {
        if (manufacturer.equals("Cisco")) {
            return "1.3.6.1.2.1.25.3.5.1.4.1";
        } else if (manufacturer.equals("Juniper")) {
            return "1.3.6.1.2.1.25.3.5.1.4.2";
        } else if (manufacturer.equals("CustomVendor")) {
            return "1.3.6.1.2.1.25.3.5.1.4.3";
        } else if (manufacturer.equals("d-link")) {
            return "1.3.6.1.4.1.171.10.134.1.1.7.2.0";
        } else {
            return null;
        }
    }

    private void updateStatus(String message) {
        statusTextArea.append(message + "\n");
        statusTextArea.setCaretPosition(statusTextArea.getDocument().getLength());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new SwitchConfigRetriever().setVisible(true);
            }
        });
    }
}
