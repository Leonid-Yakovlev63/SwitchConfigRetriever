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
    private JButton developerInfoButton;
    private JTextArea statusTextArea;
    private JTextField subnetField;
    private JTextField startIPField;
    private JTextField endIPField;
    private JTextField communityStringField;

    public SwitchConfigRetriever() {
        super("Switch Config Retriever");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
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

        developerInfoButton = new JButton("Info");
        developerInfoButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createDeveloperInfoWindow();
            }
        });

        statusTextArea = new JTextArea();
        statusTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusTextArea);

        subnetField = new JTextField("192.168.200");
        subnetField.setToolTipText("Enter the subnet");
        startIPField = new JTextField("1");
        startIPField.setToolTipText("Enter the starting IP address");
        endIPField = new JTextField("254");
        endIPField.setToolTipText("Enter the ending IP address");
        communityStringField = new JTextField("public");
        communityStringField.setToolTipText("Enter the community string");

        JPanel inputPanel = new JPanel(new GridLayout(4, 2));
        inputPanel.add(new JLabel("Subnet:"));
        inputPanel.add(subnetField);
        inputPanel.add(new JLabel("Start IP:"));
        inputPanel.add(startIPField);
        inputPanel.add(new JLabel("End IP:"));
        inputPanel.add(endIPField);
        inputPanel.add(new JLabel("Community String:"));
        inputPanel.add(communityStringField);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(startButton);
        buttonPanel.add(developerInfoButton);

        setLayout(new BorderLayout());
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void retrieveSwitchConfigs() {
        String saveDirectory = "C:\\SwitchConfigs";
        String subnet = subnetField.getText();
        int startIP = Integer.parseInt(startIPField.getText());
        int endIP = Integer.parseInt(endIPField.getText());
        String communityString = communityStringField.getText();
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
                    updateStatus("Failed to retrieve sysInfo for switch: " + ipAddress);
                }
            } catch (IOException ex) {
                updateStatus("Failed to communicate with switch: " + ipAddress + " - " + ex.getMessage());
            }
        }
        updateStatus("Switch config retrieval completed.");
    }

    private void createManufacturerDirectories(String saveDirectory) {
        File directory = new File(saveDirectory);
        if (!directory.exists()) {
            directory.mkdirs();
        }
    }

    private String getManufacturerDirectory(String saveDirectory, String manufacturer) {
        String manufacturerDirectory = saveDirectory + File.separator + manufacturer;
        File directory = new File(manufacturerDirectory);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        return manufacturerDirectory;
    }

    private String getConfigOID(String manufacturer) {
        if (manufacturer.equals("Cisco")) {
            return "1.3.6.1.4.1.9.9.43.1.1.1.0";
        } else if (manufacturer.equals("Juniper")) {
            return "1.3.6.1.4.1.2636.3.1.13.1.8";
        } else {
            return null;
        }
    }

    private void updateStatus(String status) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                statusTextArea.append(status + "\n");
            }
        });
    }

    private void createDeveloperInfoWindow() {
        JFrame developerInfoFrame = new JFrame("Info");
        developerInfoFrame.setSize(400, 200);
        developerInfoFrame.setLocationRelativeTo(this);

        JTextArea developerInfoTextArea = new JTextArea();

        developerInfoTextArea.setEditable(false);
        developerInfoTextArea.append("Email: switchconfigretriever@gmail.com\n");
        developerInfoTextArea.append("Version: 0.1\n");
        JScrollPane scrollPane = new JScrollPane(developerInfoTextArea);

        developerInfoFrame.getContentPane().add(scrollPane);
        developerInfoFrame.setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                SwitchConfigRetriever switchConfigRetriever = new SwitchConfigRetriever();
                switchConfigRetriever.setVisible(true);
            }
        });
    }
}
