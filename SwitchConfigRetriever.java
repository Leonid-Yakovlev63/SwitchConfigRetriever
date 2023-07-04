import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import org.apache.commons.net.telnet.TelnetClient;

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
    private JButton telnetButton;

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

        telnetButton = new JButton("Telnet");
        telnetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                telnetToSwitchDialog();
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
        buttonPanel.add(telnetButton);
        buttonPanel.add(infoButton);
        terminalTextArea = new JTextArea();
        terminalTextArea.setEditable(false);
        JScrollPane terminalScrollPane = new JScrollPane(terminalTextArea);
        setLayout(new BorderLayout());
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
        add(terminalScrollPane, BorderLayout.EAST);

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

        for (int i = startIP; i <= endIP; i++) {
            String ipAddress = subnet + "." + i;
            appendStatus("Checking: " + ipAddress);

            try {
                TelnetClient telnetClient = new TelnetClient();
                telnetClient.setDefaultTimeout(1000);
                telnetClient.connect(ipAddress, 23);

                appendStatus("Connected to: " + ipAddress);

                InputStream in = telnetClient.getInputStream();
                OutputStream out = telnetClient.getOutputStream();

                byte[] buff = new byte[1024];
                int ret_read;

                String login = loginField.getText();
                String password = new String(passwordField.getPassword());

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }

                out.write((login + "\r\n").getBytes());
                out.flush();
                appendTerminal(login);

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

                out.write(("terminal length 0\r\n").getBytes());
                out.flush();
                appendTerminal("terminal length 0");

                ret_read = in.read(buff);
                if (ret_read > 0) {
                    appendTerminal(new String(buff, 0, ret_read));
                }

                out.write(("show running-config\r\n").getBytes());
                out.flush();
                appendTerminal("show running-config");

                ret_read = in.read(buff);
                while (ret_read >= 0) {
                    if (ret_read > 0) {
                        appendTerminal(new String(buff, 0, ret_read));
                    }
                    ret_read = in.read(buff);
                }

                telnetClient.disconnect();
                appendStatus("Disconnected from: " + ipAddress);

            } catch (SocketException e) {
                appendStatus("Connection failed: " + e.getMessage());
            } catch (IOException e) {
                appendStatus("IO error: " + e.getMessage());
            }
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

    private void telnetToSwitchDialog() {
        String ipAddress = JOptionPane.showInputDialog(this, "Enter the IP address of the switch:");

        if (ipAddress != null && !ipAddress.isEmpty()) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    telnetToSwitch(ipAddress);
                }
            }).start();
        }
    }

    private void telnetToSwitch(String ipAddress) {
        try {
            TelnetClient telnetClient = new TelnetClient();
            telnetClient.setDefaultTimeout(1000);
            telnetClient.connect(ipAddress, 23);

            appendStatus("Connected to: " + ipAddress);

            InputStream in = telnetClient.getInputStream();
            OutputStream out = telnetClient.getOutputStream();

            byte[] buff = new byte[1024];
            int ret_read;

            String login = loginField.getText();
            String password = new String(passwordField.getPassword());

            ret_read = in.read(buff);
            if (ret_read > 0) {
                appendTerminal(new String(buff, 0, ret_read));
            }

            out.write((login + "\r\n").getBytes());
            out.flush();
            appendTerminal(login);

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

            while (true) {
                String command = JOptionPane.showInputDialog(this, "Enter a command (or 'exit' to exit):");

                if (command != null && !command.isEmpty()) {
                    if (command.equalsIgnoreCase("exit")) {
                        break;
                    } else {
                        out.write((command + "\r\n").getBytes());
                        out.flush();
                        appendTerminal(command);

                        ret_read = in.read(buff);
                        while (ret_read >= 0) {
                            if (ret_read > 0) {
                                appendTerminal(new String(buff, 0, ret_read));
                            }
                            ret_read = in.read(buff);
                        }
                    }
                } else {
                    break;
                }
            }

            telnetClient.disconnect();
            appendStatus("Disconnected from: " + ipAddress);

        } catch (SocketException e) {
            appendStatus("Connection failed: " + e.getMessage());
        } catch (IOException e) {
            appendStatus("IO error: " + e.getMessage());
        }
    }
}
