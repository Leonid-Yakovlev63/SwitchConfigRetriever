package org.example;

import org.apache.commons.net.telnet.TelnetClient;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.SocketException;
public class SwitchConfigRetriever extends JFrame {
    private JButton startButton;
    private JButton infoButton;
    private JTextArea statusTextArea;
    private JTextField subnetField;
    private JTextField startIPField;
    private JTextField endIPField;
    private JTextField loginField;
    private JPasswordField passwordField;
    private JTextArea terminalTextArea;
    private JButton terminalButton;

    public SwitchConfigRetriever() {
        super("Switch Config Retriever");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 400);
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

        infoButton = new JButton("Info");
        infoButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                infoWindow();
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
        subnetField.setToolTipText("Enter the subnet");
        startIPField = new JTextField("1");
        startIPField.setToolTipText("Enter the starting IP address");
        endIPField = new JTextField("254");
        endIPField.setToolTipText("Enter the ending IP address");
        loginField = new JTextField("admin");
        loginField.setToolTipText("Enter the login");
        passwordField = new JPasswordField("QWEqwe12345");
        passwordField.setToolTipText("Enter the password");
        JPanel inputPanel = new JPanel(new GridLayout(5, 2));
        inputPanel.add(new JLabel("Subnet:"));
        inputPanel.add(subnetField);
        inputPanel.add(new JLabel("Start IP:"));
        inputPanel.add(startIPField);
        inputPanel.add(new JLabel("End IP:"));
        inputPanel.add(endIPField);
        inputPanel.add(new JLabel("Login:"));
        inputPanel.add(loginField);
        inputPanel.add(new JLabel("Password:"));
        inputPanel.add(passwordField);
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(startButton);
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

    private void retrieveSwitchConfigs() {
        String subnet = subnetField.getText();
        int startIP = Integer.parseInt(startIPField.getText());
        int endIP = Integer.parseInt(endIPField.getText());
        String folderPath = "C:/SwitchConfigs/";
        File folder = new File(folderPath);
        if (!folder.exists()) {
            if (folder.mkdir()) {
                appendStatus("SwitchConfigs folder created");
            } else {
                appendStatus("Failed to create SwitchConfigs folder");
                return;
            }
        }

        for (int i = startIP; i <= endIP; i++) {
            String ipAddress = subnet + "." + i;
            appendStatus("Checking: " + ipAddress);

            try {
                TelnetClient telnetClient = new TelnetClient();
                telnetClient.setDefaultTimeout(1500);
                telnetClient.connect(ipAddress, 23);
                appendStatus("Connected to: " + ipAddress);

                InputStream in = telnetClient.getInputStream(); /* Потоковая штука */
                OutputStream out = telnetClient.getOutputStream(); /* Ждать пока коммутатор что-то отправит, добавить буфер */
                byte[] buff = new byte[1024];
                int ret_read;

                String login = loginField.getText(); /*Вывести в константу*/
                String password = new String(passwordField.getPassword());
                try {
                    Thread.sleep(500);  /*Даём потоку подождать*/
                } catch (InterruptedException e) {

                }
                ret_read = in.read(buff);

                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }


                out.write((login + "\r\n").getBytes());
                out.flush();
                appendTerminal(login);
                try {
                    Thread.sleep(500);  /*Даём потоку подождать*/
                } catch (InterruptedException e) {

                }
                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }

                out.write((password + "\r\n").getBytes());
                out.flush();
                appendTerminal(password);

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }

                out.write(("\r\n").getBytes());
                out.flush();
                appendTerminal("");

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }
                try {
                    Thread.sleep(1500);  /*Даём потоку подождать*/
                } catch (InterruptedException e) {

                }
                out.write(("show config current_config\r\n").getBytes());
                out.flush();
                appendTerminal("show config current_config");

                ret_read = in.read(buff);
                StringBuilder configBuilder = new StringBuilder();
                while (ret_read >= 0) {
                    if (ret_read > 0) {
                        configBuilder.append(new String(buff, 0, ret_read));
                    }
                    ret_read = in.read(buff);
                }

                String config = configBuilder.toString();
                String configFileName = ipAddress + ".txt";
                String filePath = folderPath + configFileName;
                saveConfigurationToFile(config, filePath);

                telnetClient.disconnect();
                appendStatus("Disconnected from: " + ipAddress);
            } catch (SocketException e) {
                appendStatus("Connection failed: " + e.getMessage());
            } catch (IOException e) {
                appendStatus("IO error: " + e.getMessage());
            }
        }
    }
    private void saveConfigurationToFile(String config, String ipAddress) {
        try {
            String filePath = ipAddress;
            File file = new File(filePath);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(config.getBytes());
            fos.close();
            appendStatus("Configuration saved to: " + file.getAbsolutePath());
        } catch (IOException e) {
            appendStatus("Failed to save configuration: " + e.getMessage());
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
            }
        });
    }


    private void appendTerminal(String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                terminalTextArea.append(message);
            }
        });
    }

    private void infoWindow() {
        JOptionPane.showMessageDialog(this, "");
    }

}
/*
*
* */
