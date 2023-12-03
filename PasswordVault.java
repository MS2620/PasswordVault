import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;
import java.security.spec.KeySpec;
import java.util.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Timer;

public class PasswordVault extends JFrame {
    private Map<String, String[]> passwords;
    private SecretKey secretKey;
    private JPasswordField masterPasswordField, passwordField;
    private JTextField websiteField, usernameField;
    private boolean isMasterPasswordSet;
    private DefaultTableModel tableModel;
    private JTable dataTable;
    private JTextField searchField;
    Path masterPasswordFile = Paths.get(System.getProperty("user.home"), "masterpassword.txt");

    public PasswordVault(String title) {
        super(title);
        passwords = new HashMap<>();

        // Always initialize the set master password UI
        initializeSetMasterPasswordUI();
        setApplicationIcon();
    }

    private void initializeSetMasterPasswordUI() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(3, 2));

        add(new JLabel("Master Password:"));
        masterPasswordField = new JPasswordField();
        add(masterPasswordField);

        JButton setMasterPasswordButton = new JButton("Enter Master Password");
        setMasterPasswordButton.addActionListener(e -> checkMasterPassword());
        add(setMasterPasswordButton);

        pack();
        setLocationRelativeTo(null);
    }

    private void initializeMainUI() {
        getContentPane().removeAll();
        setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));

        JPanel inputPanel = new JPanel(new GridLayout(4, 2));
        inputPanel.add(new JLabel("Website:"));
        websiteField = new JTextField();
        inputPanel.add(websiteField);

        inputPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        inputPanel.add(usernameField);

        inputPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        inputPanel.add(passwordField);

        inputPanel.add(new JButton("Save Password") {
            {
                addActionListener(e -> savePassword());
            }
        });

        inputPanel.add(new JButton("Get Password") {
            {
                addActionListener(e -> getPassword());
            }
        });

        add(inputPanel);

        // Create a panel for buttons with FlowLayout
        JPanel buttonPanel = new JPanel(new FlowLayout());

        // Add "Delete Entry" button
        JButton deleteEntryButton = new JButton("Delete Entry");
        deleteEntryButton.addActionListener(e -> deleteSelectedEntry());
        buttonPanel.add(deleteEntryButton);

        // Add "Delete All" button
        JButton deleteAllButton = new JButton("Delete All");
        deleteAllButton.addActionListener(e -> deleteAllEntries());
        buttonPanel.add(deleteAllButton);

        // Add the button panel to the main UI
        add(buttonPanel);

        JPanel searchPanel = new JPanel(new FlowLayout());
        searchPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchPanel.add(searchField);
        JButton searchButton = new JButton("Search");
        searchButton.addActionListener(e -> searchPasswords());
        searchPanel.add(searchButton);
        add(searchPanel);

        if (dataTable == null) {
            tableModel = new DefaultTableModel(new Object[] { "Website", "Username", "Password" }, 0);
            dataTable = new JTable(tableModel);
        } else if (tableModel == null) {
            tableModel = new DefaultTableModel(new Object[] { "Website", "Username", "Password" }, 0);
            dataTable.setModel(tableModel);
        }

        tableModel = new DefaultTableModel(new Object[] { "Website", "Username", "Password" }, 0);

        dataTable = new JTable(tableModel);
        dataTable.setPreferredScrollableViewportSize(new Dimension(400, 200));
        add(new JScrollPane(dataTable));

        pack();
        setLocationRelativeTo(null);
    }

    private void deleteSelectedEntry() {
        int selectedRow = dataTable.getSelectedRow();
        if (selectedRow >= 0) {
            String website = (String) tableModel.getValueAt(selectedRow, 0);
            tableModel.removeRow(selectedRow);
            passwords.remove(website);
            savePasswordsToFile();
            JOptionPane.showMessageDialog(this, "Entry deleted successfully!");
        } else {
            JOptionPane.showMessageDialog(this, "Please select an entry to delete.");
        }
    }

    private void deleteAllEntries() {
        int confirmDialogResult = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete all entries?", "Confirm Deletion", JOptionPane.YES_NO_OPTION);

        if (confirmDialogResult == JOptionPane.YES_OPTION) {
            tableModel.setRowCount(0);
            passwords.clear();
            savePasswordsToFile();
            JOptionPane.showMessageDialog(this, "All entries deleted successfully!");
        }
    }

    private void searchPasswords() {
        String searchQuery = searchField.getText().toLowerCase();
        if (searchQuery.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a search query.");
            return;
        }

        List<String[]> searchResults = new ArrayList<>();

        for (Map.Entry<String, String[]> entry : passwords.entrySet()) {
            String website = entry.getKey().toLowerCase();
            if (website.contains(searchQuery)) {
                String[] result = new String[3];
                result[0] = website;
                result[1] = entry.getValue()[0]; // Username
                result[2] = entry.getValue()[1]; // Encrypted Password
                searchResults.add(result);
            }
        }

        if (searchResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No matching passwords found.");
        } else {
            showSearchResults(searchResults);
        }
    }

    private void showSearchResults(List<String[]> searchResults) {
        if (searchResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No matching passwords found.");
            return;
        }

        String[] columnNames = { "Website", "Username", "Encrypted Password" };
        Object[][] data = searchResults.stream()
                .map(result -> new Object[] { result[0], result[1], result[2] })
                .toArray(Object[][]::new);

        DefaultTableModel tableModel = new DefaultTableModel(data, columnNames);
        JTable resultTable = new JTable(tableModel);

        JButton decryptButton = new JButton("Decrypt Password");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = resultTable.getSelectedRow();
                if (selectedRow >= 0) {
                    String website = (String) tableModel.getValueAt(selectedRow, 0);
                    String[] storedData = passwords.get(website);
                    if (storedData != null) {
                        String encryptedPassword = storedData[1];

                        try {
                            String decryptedPassword = decrypt(encryptedPassword);
                            tableModel.setValueAt(decryptedPassword, selectedRow, 2);

                            // Schedule a task to re-encrypt the password after 30 seconds
                            Timer timer = new Timer();
                            timer.schedule(new TimerTask() {
                                @Override
                                public void run() {
                                    try {
                                        // Re-encrypt the password and update the table
                                        String reEncryptedPassword = encrypt(decryptedPassword);
                                        tableModel.setValueAt(reEncryptedPassword, selectedRow, 2);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    } finally {
                                        timer.cancel(); // Terminate the timer after the task is executed
                                    }
                                }
                            }, 10000); // 10 seconds
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            JOptionPane.showMessageDialog(null, "Failed to decrypt password." + JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
        });

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(resultTable), BorderLayout.CENTER);
        panel.add(decryptButton, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(this, panel, "Search Results", JOptionPane.PLAIN_MESSAGE);
    }

    private void setFileHiddenAttribute(Path filePath) throws IOException {
        try {
            // Attempt to set the hidden attribute using DosFileAttributeView
            DosFileAttributeView dosView = Files.getFileAttributeView(filePath, DosFileAttributeView.class);
            if (dosView != null) {
                DosFileAttributes dosAttributes = dosView.readAttributes();
                dosView.setHidden(true);
            }
        } catch (Exception e) {
            // Ignore if DosFileAttributeView is not supported (e.g., on Unix-like systems)
        }
    }

    private boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    private void checkMasterPassword() {
        String masterPassword = new String(masterPasswordField.getPassword());
        try {

            if (Files.exists(masterPasswordFile)) {
                byte[] savedPasswordBytes = Files.readAllBytes(masterPasswordFile);
                String savedPassword = new String(savedPasswordBytes);

                if (masterPassword.equals(savedPassword)) {
                    secretKey = generateSecretKey(masterPassword);
                    JOptionPane.showMessageDialog(this, "Master password accepted. You can now perform actions.");
                    isMasterPasswordSet = true;
                    initializeMainUI(); // Call initializeMainUI before updateDataTable
                    loadPasswordsFromFile(); // Load saved passwords from file
                    updateDataTable();
                } else {
                    JOptionPane.showMessageDialog(this, "Incorrect master password. Please try again.");
                }
                if (isWindows()) {
                    setFileHiddenAttribute(masterPasswordFile);
                }
            } else {
                Files.write(masterPasswordFile, masterPassword.getBytes());
                secretKey = generateSecretKey(masterPassword);
                JOptionPane.showMessageDialog(this, "Master password set successfully.");
                isMasterPasswordSet = true;
                initializeMainUI(); // Call initializeMainUI before updateDataTable
                if (isWindows()) {
                    setFileHiddenAttribute(masterPasswordFile);
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error checking master password. Please try again.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private SecretKey generateSecretKey(String masterPassword) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), masterPassword.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }

    private void savePassword() {
        if (!isMasterPasswordSet) {
            JOptionPane.showMessageDialog(this, "Please enter the master password first.");
            return;
        }

        String website = websiteField.getText();
        String username = usernameField.getText();
        String password = new String(passwordField.getPassword());

        try {
            if (secretKey == null) {
                JOptionPane.showMessageDialog(this,
                        "Error: Master password not properly set. Please restart the application.");
                return;
            }

            String encryptedPassword = encrypt(password);
            tableModel.addRow(new Object[] { website, username, encryptedPassword });
            passwords.put(website, new String[] { username, encryptedPassword });

            // Save the password to the file
            savePasswordsToFile();

            JOptionPane.showMessageDialog(this, "Password saved successfully!");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error saving password. Please try again.");
            e.printStackTrace();
        }
    }

    private void getPassword() {
        if (!isMasterPasswordSet) {
            JOptionPane.showMessageDialog(this, "Please enter the master password first.");
            return;
        }

        int selectedRow = dataTable.getSelectedRow();
        if (selectedRow >= 0) {
            String website = (String) tableModel.getValueAt(selectedRow, 0);
            String[] storedData = passwords.get(website);
            if (storedData != null) {
                String username = storedData[0];
                String encryptedPassword = storedData[1];

                try {
                    String decryptedPassword = decrypt(encryptedPassword);

                    // Update the decrypted password directly in the table
                    tableModel.setValueAt(decryptedPassword, selectedRow, 2);

                    // Schedule a task to re-encrypt the password after 30 seconds
                    Timer timer = new Timer();
                    timer.schedule(new TimerTask() {
                        @Override
                        public void run() {
                            try {
                                // Re-encrypt the password and update the table
                                String reEncryptedPassword = encrypt(decryptedPassword);
                                tableModel.setValueAt(reEncryptedPassword, selectedRow, 2);
                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                timer.cancel(); // Terminate the timer after the task is executed
                            }
                        }
                    }, 10000); // 10 seconds
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void updateDataTable() {
        if (tableModel == null) {
            tableModel = new DefaultTableModel(new Object[] { "Website", "Username", "Password" }, 0);
            dataTable.setModel(tableModel);
        }

        for (Map.Entry<String, String[]> entry : passwords.entrySet()) {
            String website = entry.getKey();
            String[] storedData = entry.getValue();
            String username = storedData[0];
            String encryptedPassword = storedData[1];
            tableModel.addRow(new Object[] { website, username, encryptedPassword });
        }
    }

    private void savePasswordsToFile() {
        String fileName = System.getProperty("user.home") + File.separator + "passwords.txt";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            for (Map.Entry<String, String[]> entry : passwords.entrySet()) {
                String website = entry.getKey();
                String[] storedData = entry.getValue();
                String username = storedData[0];
                String encryptedPassword = storedData[1];
                writer.write(website + "," + username + "," + encryptedPassword);
                writer.newLine();
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error saving passwords to file.");
            e.printStackTrace();
        }
    }

    private void loadPasswordsFromFile() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader(System.getProperty("user.home") + File.separator + "passwords.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 3) {
                    String website = parts[0];
                    String username = parts[1];
                    String encryptedPassword = parts[2];
                    passwords.put(website, new String[] { username, encryptedPassword });
                }
            }
            // Set the "passwords.txt" file as hidden on Windows
            if (isWindows()) {
                setFileHiddenAttribute(Paths.get("passwords.txt"));
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error loading passwords from file.");
            e.printStackTrace();
        }
    }

    private void setApplicationIcon() {
        try {
            // Load the original image from the file
            BufferedImage originalIcon = ImageIO.read(Objects.requireNonNull(getClass().getResourceAsStream("logo.png")));

            // Resize the image to your preferred dimensions (e.g., 48x48)
            int width = 48;
            int height = 48;
            BufferedImage resizedIcon = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = resizedIcon.createGraphics();
            g.drawImage(originalIcon, 0, 0, width, height, null);
            g.dispose();

            // Set the resized image as the icon for the JFrame
            setIconImage(resizedIcon);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new PasswordVault("Password Vault").setVisible(true);
            }
        });
    }
}
