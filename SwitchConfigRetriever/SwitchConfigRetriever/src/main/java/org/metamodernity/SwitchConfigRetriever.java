package org.metamodernity;
import org.metamodernity.filter.IntFilter;
import org.apache.commons.net.telnet.TelnetClient;
import javax.swing.*;
import javax.swing.text.PlainDocument;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.SocketException;
import java.net.URI;
import java.nio.file.Paths;
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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import javax.swing.event.HyperlinkEvent;
public class SwitchConfigRetriever extends JFrame {
    final JTextArea statusTextArea;
    final JTextArea terminalTextArea;
    final JTextField subnetField;
    final JTextField startIPField;
    final JTextField endIPField;
    final JTextField loginField;

    final JTextField TFTPserverIPField;
    final JPasswordField passwordField;
    final JButton startButton;
    final JButton pauseButton;
    final JButton infoButton;
    final JButton terminalButton;

    private Thread retrieverThread;
    private Thread controllerThread;
    final HashMap<String, HashMap<String, String>> configMap = new HashMap<>();
    final String folderPath = "C:/SwitchConfigs/";
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
                infoWindow("For the program to work, you will need a TFTP server.<br>Source Code: <a href=\"https://github.com/metamodernity/SwitchConfigRetriever\">https://github.com/metamodernity/SwitchConfigRetriever/</a><br>Documentation: <a href=\"https://metamodernity.github.io/SwitchConfigRetriever/\">https://metamodernity.github.io/SwitchConfigRetriever/</a><br>Version: 0.1");
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

        subnetField = new JTextField("192.168.200");
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
        dlinkDevices.put("1.3.6.1.4.1.171.10.117.4.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.44.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.14.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("11.3.6.1.4.1.171.10.75.14.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.133.5.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.18.1", "upload cfg_toTFTP %s %s[%s].cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.32.1", "upload cfg_toTFTP %s %s[%s].cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.76.19.1", "upload cfg_toTFTP %s %s[%s].cfg"); //проверить
        dlinkDevices.put("1.3.6.1.4.1.171.10.134.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.5.2", "upload cfg_toTFTP %s %s[%s].cfg");
        dlinkDevices.put("1.3.6.1.4.1.171.10.116.2", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.153.4.1", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.15.3", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        dlinkDevices.put("1.3.6.1.4.1.171.10.75.15.2", "upload cfg_toTFTP %s %s[%s].cfg config_id 1");
        /*
        * 192.168.200.60
        192.168.200.68
        192.168.200.73
        192.168.200.163
        192.168.200.164
        192.168.200.169
        * */
        configMap.put("D-Link", dlinkDevices);

        HashMap<String, String> juniperDevices = new HashMap<>();
        juniperDevices.put("1.3.6.1.4.1.2636.1.1.1.2.44", "file copy /var/tmp/config.cfg tftp://%s/%s[%s].cfg");
        configMap.put("Juniper", juniperDevices);

        HashMap<String, String> ciscoDevices = new HashMap<>();
        ciscoDevices.put("EX8200", "copy running-config tftp %s %s[%s].cfg");
        ciscoDevices.put("EX3300", "copy running-config tftp %s %s[%s].cfg");
        ciscoDevices.put("EX3200", "copy running-config tftp %s %s[%s].cfg");
        configMap.put("Cisco", ciscoDevices);

        HashMap<String, String> microTikDevices = new HashMap<>();
        microTikDevices.put("1.3.6.1.4.1.14988.1", "/export compact");
        configMap.put("MicroTik", microTikDevices);

        HashMap<String, String> eltexDevices = new HashMap<>();
        eltexDevices.put("1.3.6.1.4.1.35265.1.52", "copy running-config tftp://%s/%s[%s].cfg");
        eltexDevices.put("1.3.6.1.4.1.35265.1.89", "copy running-config tftp://%s/%s[%s].cfg");
        eltexDevices.put("1.3.6.1.4.1.35265.1.76", "copy running-config tftp://%s/%s[%s].cfg");
        eltexDevices.put("1.3.6.1.4.1.890.1.5.8.68", "copy running-config tftp://%s/%s[%s].cfg");
        eltexDevices.put("1.3.6.1.4.1.35265.1.81", "copy running-config tftp://%s/%s[%s].cfg");
        eltexDevices.put("1.3.6.1.4.1.35265.1.83", "copy running-config tftp://%s/%s[%s].cfg");
        configMap.put("Eltex", eltexDevices);

    }

    // Метод для получения производителя по SNMP
    private String getSwitchManufacturer(String ipAddress) throws IOException {
        String community = "public";
        String oidSysDescr = "1.3.6.1.2.1.1.1.0";
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

    // Переписал метод для формирования команды, теперь он учитывает дату и время
    private String getCommandWithDateTime(String manufacturer, String sysObjectID, String ipAddress) {
        String TFTPserverIP = TFTPserverIPField.getText();
        HashMap<String, String> deviceMap = configMap.get(manufacturer);

        if (deviceMap != null) {
            String command = deviceMap.get(sysObjectID);

            if (command != null) {
                command = String.format(command, TFTPserverIP, ipAddress, getCurrentDateTime());
                return command;
            }
        }

        return String.format("upload cfg_toTFTP %s %s[%s].cfg config_id 1", TFTPserverIP, ipAddress, getCurrentDateTime());
    }
    // Метод для получения текущей даты и времени
    private String getCurrentDateTime() {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy_HH-mm");
        return sdf.format(new Date());
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
                // Получение имени устройства
                String deviceName = getInfoBySNMP(ipAddress, ".1.3.6.1.2.1.1.5.0");
                String sysName = getInfoBySNMP(ipAddress, "1.3.6.1.2.1.1.1.0");
                String sysObjectID = getInfoBySNMP(ipAddress, ".1.3.6.1.2.1.1.2.0");
                // Формирование команды к коммутатору
                String command = getCommandWithDateTime(manufacturer, sysObjectID, ipAddress);

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
                threadSleep(500);
                byte[] buff = new byte[1024];
                int ret_read;

                threadSleep(500);
                ret_read = in.read(buff);

                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                PrintWriter writer = new PrintWriter(out, true);

                writer.println(login);
                threadSleep(500);

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                writer.println(password);
                threadSleep(500);

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                out.write(("\r\n").getBytes());
                out.flush();
                threadSleep(500);
                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
                }

                threadSleep(500);
                writer.println(command);
                threadSleep(500);

                out.write((command + "\r\n").getBytes());
                out.flush();
                appendTerminal(command);
                threadSleep(3000);
                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read, "UTF-8"));
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
        appendStatus("===========================");
    }

    private String getInfoBySNMP(String ipAddress, String oidSys) throws IOException {
        String community = "public";
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

    private void threadSleep(int sleepTime){
        try {
            Thread.sleep(sleepTime);  //Даём потоку подождать
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void openTerminal(String command) {
        try {
            // Создаем процесс, выполняющий команду открытия терминала с заданной командой
            ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", "start", "cmd", "/k", command);
            processBuilder.inheritIO();
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
        // Создаем компонент для отображения HTML-разметки
        JEditorPane editorPane = new JEditorPane("text/html", message);
        editorPane.setEditable(false);

        // Добавляем обработчик события для ссылок
        editorPane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                try {
                    // Открываем ссылку в браузере
                    Desktop.getDesktop().browse(e.getURL().toURI());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        // Отображаем диалоговое окно с компонентом содержащим HTML-разметку
        JOptionPane.showMessageDialog(this, editorPane, "Information", JOptionPane.INFORMATION_MESSAGE);
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
