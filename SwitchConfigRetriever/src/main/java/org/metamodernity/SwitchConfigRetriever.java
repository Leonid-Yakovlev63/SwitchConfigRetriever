package org.metamodernity;

import org.metamodernity.filter.IntFilter;

import org.apache.commons.net.telnet.TelnetClient;
import org.apache.commons.net.tftp.TFTP;
import org.apache.commons.net.tftp.TFTPClient;

import org.json.simple.*;
import org.json.simple.parser.JSONParser;

import javax.swing.*;
import javax.swing.text.PlainDocument;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.SocketException;
import java.util.HashMap;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SwitchConfigRetriever extends JFrame {
    private JTextArea statusTextArea;
    private JTextArea terminalTextArea;
    private JTextField subnetField;
    private JTextField startIPField;
    private JTextField endIPField;
    private JTextField loginField;

    private JTextField TFTPserverIPField;
    private JPasswordField passwordField;
    private JButton startButton;
    private JButton pauseButton;
    private JButton infoButton;
    private JButton terminalButton;

    private Thread retrieverThread;
    private Thread controllerThread;
    private HashMap<String, HashMap<String, String>> configMap = new HashMap<>();
    private String folderPath = "C:/SwitchConfigs/";
    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;

    public SwitchConfigRetriever() {
        super("Switch Config Retriever");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 400);
        setLocationRelativeTo(null);

        startButton = new JButton("Start");
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!isRunning) {
                    isRunning = true;
                    startButton.setText("Stop");
                    pauseButton.setVisible(true);

                    retrieverThread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                retrieveSwitchConfigs();
                            } catch (InterruptedException ex) {
                                throw new RuntimeException(ex);
                            }
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    if (isRunning) {
                                        isRunning = false;
                                        isPaused = false;
                                        startButton.setText("Start");
                                        pauseButton.setVisible(false);
                                    }
                                }
                            });
                        }
                    });

                    controllerThread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            retrieverThread.start();
                        }
                    });

                    controllerThread.start();
                }
                else {
                    isRunning = false;
                    isPaused = false;
                    startButton.setEnabled(false);
                    startButton.setText("Start");
                    pauseButton.setVisible(false);
                    appendStatus("Waiting for check to finish...");
                }
            }
        });

        pauseButton = new JButton("Pause");
        pauseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isRunning) {
                    if (!isPaused) {
                        isPaused = true;
                        pauseButton.setEnabled(false);
                        pauseButton.setText("Resume");
                        appendStatus("Waiting for check to pause...");
                    }
                    else {
                        isPaused = false;
                        pauseButton.setText("Pause");
                        appendStatus("Resumed");
                    }
                }
            }
        });
        pauseButton.setVisible(false);

        infoButton = new JButton("Info");
        infoButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                infoWindow("Абоба");
            }
        });

        terminalButton = new JButton("Terminal");
        terminalButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openTerminal("cd /d C:/");
            }
        });


        statusTextArea = new JTextArea();
        statusTextArea.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(statusTextArea);

        subnetField = new JTextField("192.168.200"); //"192.168.200"
        ((PlainDocument) subnetField.getDocument()).setDocumentFilter(new IntFilter(true));
        subnetField.setToolTipText("Enter the subnet");

        startIPField = new JTextField("1");
        ((PlainDocument) startIPField.getDocument()).setDocumentFilter(new IntFilter(false));
        startIPField.setToolTipText("Enter the starting IP address");

        endIPField = new JTextField("254");
        ((PlainDocument) endIPField.getDocument()).setDocumentFilter(new IntFilter(false));
        endIPField.setToolTipText("Enter the ending IP address");

        TFTPserverIPField = new JTextField("192.168.1.195");
        TFTPserverIPField.setToolTipText("Enter the IP address of TFTP server");

        loginField = new JTextField("admin");
        loginField.setToolTipText("Enter the login");

        passwordField = new JPasswordField("QWEqwe12345");
        passwordField.setToolTipText("Enter the password");

        JPanel inputPanel = new JPanel(new GridLayout(6, 2));

        inputPanel.add(new JLabel("Subnet:"));
        inputPanel.add(subnetField);
        inputPanel.add(new JLabel("Start IP:"));
        inputPanel.add(startIPField);
        inputPanel.add(new JLabel("End IP:"));
        inputPanel.add(endIPField);
        inputPanel.add(new JLabel("TFTP server:"));
        inputPanel.add(TFTPserverIPField);
        inputPanel.add(new JLabel("Login:"));
        inputPanel.add(loginField);
        inputPanel.add(new JLabel("Password:"));
        inputPanel.add(passwordField);

        JPanel controlButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlButtonPanel.add(startButton);
        controlButtonPanel.add(pauseButton);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(controlButtonPanel);
        buttonPanel.add(terminalButton);
        buttonPanel.add(infoButton);

        terminalTextArea = new JTextArea();
        terminalTextArea.setEditable(false);

        JScrollPane terminalScrollPane = new JScrollPane(terminalTextArea);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(inputPanel, BorderLayout.NORTH);
        leftPanel.add(scrollPane, BorderLayout.CENTER);
        splitPane.setLeftComponent(leftPanel);

        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(buttonPanel, BorderLayout.NORTH);
        rightPanel.add(terminalScrollPane, BorderLayout.CENTER);
        splitPane.setRightComponent(rightPanel);

        add(splitPane, BorderLayout.CENTER);

        initializeConfigMap();
    }

    private void initializeConfigMap() {

        HashMap<String, String> dlinkDevices = new HashMap<>();
        dlinkDevices.put("1.3.6.1.4.1.171.10.117.4.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.44.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.14.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("11.3.6.1.4.1.171.10.75.14.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.133.5.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.18.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.32.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.19.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.134.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.5.2", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.116.2", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.153.4.1", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.15.3", "upload cfg_toTFTP %s %s.cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.15.2", "upload cfg_toTFTP %s %s.cfg");
        configMap.put("D-Link", dlinkDevices);

        HashMap<String, String> juniperDevices = new HashMap<>();
        juniperDevices.put("1.3.6.1.4.1.2636.1.1.1.2.44", "file copy /var/tmp/config.cfg tftp://%s/%s.cfg");
        configMap.put("Juniper", juniperDevices);

        HashMap<String, String> ciscoDevices = new HashMap<>();
        ciscoDevices.put("EX8200", "show running-config");
        ciscoDevices.put("EX3300", "show running-config");
        ciscoDevices.put("EX3200", "show running-config");
        configMap.put("Cisco", ciscoDevices);

        HashMap<String, String> microTikDevices = new HashMap<>();
        microTikDevices.put("CRS354-48P-4S+2Q+RM", "/export compact");
        microTikDevices.put("CRS326-24G-2S+RM", "/export compact");
        microTikDevices.put("US-24E", "/export compact");
        configMap.put("MicroTik", microTikDevices);

        HashMap<String, String> eltexDevices = new HashMap<>();
        eltexDevices.put("1.3.6.1.4.1.35265.1.52", "copy tftp://%s /%s.cfg backup ");
        eltexDevices.put("1.3.6.1.4.1.35265.1.89", "copy tftp://%s /%s.cfg backup ");
        eltexDevices.put("1.3.6.1.4.1.35265.1.76", "copy tftp://%s /%s.cfg backup ");
        eltexDevices.put("1.3.6.1.4.1.890.1.5.8.68", "copy tftp://%s /%s.cfg backup ");
        eltexDevices.put("1.3.6.1.4.1.35265.1.81", "copy tftp://%s /%s.cfg backup ");
        eltexDevices.put("1.3.6.1.4.1.35265.1.83", "copy tftp://%s /%s.cfg backup ");
        configMap.put("Eltex", eltexDevices);

    }

    // Метод для получения производителя по SNMP
    private String getSwitchManufacturer(String ipAddress) throws IOException {
        String community = "public"; // SNMP community
        String oidSysDescr = "1.3.6.1.2.1.1.1.0"; // OID для sysDescr.0
        String manufacturer = "unknown";

        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/161");
        CommunityTarget<Address> target = new CommunityTarget<Address>();
        target.setCommunity(new OctetString(community));
        target.setAddress(targetAddress);
        target.setVersion(SnmpConstants.version2c);

        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID(oidSysDescr)));
        pdu.setType(PDU.GET);

        ResponseEvent<Address> event = snmp.send(pdu, target, null);
        if (event != null && event.getResponse() != null) {
            PDU response = event.getResponse();
            if (response.getErrorStatus() == PDU.noError) {
                VariableBinding vb = response.getVariableBindings().get(0);
                String sysDescr = vb.getVariable().toString();

                // Анализируем описание и возвращаем производителя
                if (sysDescr.contains("Cisco")) {
                    manufacturer = "Cisco";
                }
                else if (sysDescr.contains("D-Link")) {
                    manufacturer = "D-Link";
                }
                else if (sysDescr.contains("DES")) {
                    manufacturer = "D-Link";
                }
                else if (sysDescr.contains("DGS")) {
                    manufacturer = "D-Link";
                }
                else if (sysDescr.contains("Juniper")) {
                    manufacturer = "Juniper";
                }
                else if (sysDescr.contains("CRS310-1G-5S-4S+")) {
                    manufacturer = "MikroTik";
                }
                else if (sysDescr.contains("MES")) {
                    manufacturer = "Eltex";
                }
            }
        }

        snmp.close();
        return manufacturer;
    }

    private String getCommand(String manufacturer, String sysObjectID, String ipAddress) {
        String TFTPserverIP = TFTPserverIPField.getText();
        HashMap<String, String> deviceMap = configMap.get(manufacturer);

        if (deviceMap != null) {
            String command = deviceMap.get(sysObjectID);

            if (command != null) {
                command = String.format(command, TFTPserverIP, ipAddress);
                return command;
            }
        }

        return String.format("upload cfg_toTFTP %s %s.cfg", TFTPserverIP, ipAddress);
    }


    private void retrieveSwitchConfigs() throws InterruptedException {
        File folder = new File(this.folderPath);
        if (!folder.exists()) {
            if (folder.mkdir()) {
                appendStatus("SwitchConfigs folder created");
            } else {
                appendStatus("Failed to create SwitchConfigs folder");
                return;
            }
        }
        String subnet = subnetField.getText();
        int startIP = Integer.parseInt(startIPField.getText());
        int endIP = Integer.parseInt(endIPField.getText());
        String login = loginField.getText();
        String password = new String(passwordField.getPassword());
        appendStatus("===========================");
        for (int i = startIP; i <= endIP && isRunning; i++) {
            appendStatus("===========================");
            appendStatus(String.valueOf(i) + ".");
            String ipAddress = subnet + "." + i;
            appendStatus("Checking: " + ipAddress);

            try {
                // Подключение по SNMP для получения производителя
                String manufacturer = getSwitchManufacturer(ipAddress);
                // Создание папки для производителя, если её нет
                String manufacturerFolderPath = folderPath + manufacturer;
                File manufacturerFolder = new File(manufacturerFolderPath);
                if (!manufacturerFolder.exists()) {
                    if (manufacturerFolder.mkdir()) {
                        appendStatus("Created folder for manufacturer: " + manufacturer);
                    } else {
                        appendStatus("Failed to create folder for manufacturer: " + manufacturer);
                        continue;
                    }
                }
                // Получение имени устройства
                String deviceName = getInfoBySNMP(ipAddress, ".1.3.6.1.2.1.1.5.0");
                String sysName = getInfoBySNMP(ipAddress, "1.3.6.1.2.1.1.1.0");
                String sysObjectID = getInfoBySNMP(ipAddress, ".1.3.6.1.2.1.1.2.0");
                // Формирование команды к коммутатору
                String command = getCommand(manufacturer, sysObjectID, ipAddress);

                TelnetClient telnetClient = new TelnetClient();
                telnetClient.setDefaultTimeout(1500);
                telnetClient.connect(ipAddress, 23);

                appendStatus("Connected to: " + ipAddress);
                appendStatus("  Device name: " + deviceName);
                appendStatus("  Manufacturer: " + manufacturer);
                appendStatus("  sysName:" + sysName);
                appendStatus("  sysObjectID:" + sysObjectID);

                InputStream in = telnetClient.getInputStream();
                OutputStream out = telnetClient.getOutputStream();
                threadSleep();
                byte[] buff = new byte[1024];
                int ret_read;

                threadSleep();
                ret_read = in.read(buff);

                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                PrintWriter writer = new PrintWriter(out, true);

                writer.println(login);
                threadSleep();

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                writer.println(password);
                threadSleep();

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                out.write(("\r\n").getBytes());
                out.flush();
                threadSleep();
                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                threadSleep();
                writer.println(command);
                threadSleep();

                if (manufacturer != "unknown" && configMap.containsKey(manufacturer)) {
                    appendStatus("Configuration saved for: " + ipAddress);

                    out.write((command + "\r\n").getBytes());
                    out.flush();
                    appendTerminal(command);

                    out.flush();

                    ret_read = in.read(buff);
                    StringBuilder configBuilder = new StringBuilder();
                    while (ret_read >= 0) {
                        if (ret_read > 0) {
                            configBuilder.append(new String(buff, 0, ret_read, "UTF-8"));
                        }
                        ret_read = in.read(buff);
                    }

                    String config = configBuilder.toString();
                    String filePath = manufacturerFolderPath + "/" + ipAddress + ".cfg";
                    saveConfigurationToFile(config, filePath);
                }

                telnetClient.disconnect();
                appendStatus("Disconnected from: " + ipAddress);
            } catch (SocketException e) {
                appendStatus("Connection failed: " + e.getMessage());
            } catch (IOException e) {
                appendStatus("IO error: " + e.getMessage());
            }

            if (isPaused) {
                pauseButton.setEnabled(true);
                appendStatus("Paused.");
                while(isPaused) {}
            }

            if (!isRunning){
                startButton.setEnabled(true);
                appendStatus("Stopped.");
            }
            appendStatus("===========================");
        }
    }

    private String getInfoBySNMP(String ipAddress, String oidSys) throws IOException {
        String community = "public"; // SNMP community
        String sysName = "unknown";

        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/161");
        CommunityTarget<Address> target = new CommunityTarget<Address>();
        target.setCommunity(new OctetString(community));
        target.setAddress(targetAddress);
        target.setVersion(SnmpConstants.version2c);

        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID(oidSys)));
        pdu.setType(PDU.GET);

        ResponseEvent<Address> event = snmp.send(pdu, target, null);
        if (event != null && event.getResponse() != null) {
            PDU response = event.getResponse();
            if (response.getErrorStatus() == PDU.noError) {
                VariableBinding vb = response.getVariableBindings().get(0);
                sysName = vb.getVariable().toString();
            }
        }
        snmp.close();
        return sysName;
    }

    /*private void TFTPmethod() throws InterruptedException { //аналог retrieveSwitchConfigs() (пока не используется)
        String subnet = subnetField.getText();
        int startIP = Integer.parseInt(startIPField.getText());
        int endIP = Integer.parseInt(endIPField.getText());

        for (int i = startIP; i <= endIP; i++) {
            String ipAddress = subnet + "." + i;
            appendStatus("Checking: " + ipAddress);
            try {
                TFTPClient tftpClient = new TFTPClient();

                // Установка таймаута
                tftpClient.setDefaultTimeout(5000);


                String localFile = ipAddress + ".txt";
                FileOutputStream fileOutputStream = new FileOutputStream(localFile);

                // Получение конфигурации коммутатора по TFTP
                tftpClient.open();
                tftpClient.receiveFile("/config.cfg", TFTP.BINARY_MODE, fileOutputStream, ipAddress);
                fileOutputStream.close();
                tftpClient.close();

                appendStatus("Configuration saved for: " + ipAddress);

            } catch (IOException e) {
                appendStatus("Failed to retrieve configuration for: " + ipAddress + " - " + e.getMessage());
            }
        }
    }*/
    private void saveConfigurationToFile(String config, String filePath) {
        try (PrintWriter writer = new PrintWriter(filePath)) {
            writer.write(config);
            appendStatus("Configuration saved to: " + filePath);
        } catch (IOException e) {
            appendStatus("Failed to save configuration: " + e.getMessage());
        }
    }

    private void threadSleep(){
        try {
            Thread.sleep(500);  //Даём потоку подождать
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void openTerminal(String command) {
        try {
            // Создаем процесс, выполняющий команду открытия терминала с заданной командой
            ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", "start", "cmd", "/k", command);
            processBuilder.inheritIO(); // Позволяет наследовать ввод/вывод с текущего Java процесса
            processBuilder.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void appendStatus(String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                statusTextArea.append(message + "\n");
                statusTextArea.setCaretPosition(statusTextArea.getDocument().getLength()); // Установить каретку в конец текста
            }
        });
    }


    private void appendTerminal(String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                terminalTextArea.append(message);
                terminalTextArea.setCaretPosition(terminalTextArea.getDocument().getLength()); // Установить каретку в конец текста
            }
        });
    }


    private void infoWindow(String message) {
        JOptionPane.showMessageDialog(this, message);
    }

    public static void main(String[] args) {

        JSONParser parser = new JSONParser();

        try {
            JSONObject obj = (JSONObject)parser.parse(new FileReader(SwitchConfigRetriever.class.getClassLoader().getResource("commands.json").toURI().getPath()));
            System.out.println(obj.toString());
        }
        catch (Exception e) {
            System.out.println(e);
        }
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                SwitchConfigRetriever switchConfigRetriever = new SwitchConfigRetriever();
                switchConfigRetriever.setVisible(true);
            }
        });
    }
}
