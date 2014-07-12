package EncryDecry;

import java.awt.Container;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class LithasaEncryptor extends JFrame {

	private static final long serialVersionUID = 1L;
	private static final int WIDTH = 500;
	private static final int HEIGHT = 120;
	private static Cipher cipher;

	private JLabel passwordLabel;
	private JPasswordField passwordTextBox;
	private JTextField filePathTextField;
	JFileChooser fc;

	private JButton encryptButton, decryptButton, openFileButton;

	// Button handlers:
	private EncryptHandler encryptHandler;
	private DecryptHandler decryptHandler;
	private openFileHandler openFileHandler;

	public LithasaEncryptor() {
		passwordLabel = new JLabel("  Enter Encryption/Decryption Key: ",
				SwingConstants.LEFT);

		passwordTextBox = new JPasswordField(10);
		filePathTextField = new JTextField(10);
		fc = new JFileChooser();

		// Specify handlers for each button and add (register) ActionListeners
		// to each button.
		encryptButton = new JButton("Encrypt");
		encryptHandler = new EncryptHandler();
		encryptButton.addActionListener(encryptHandler);

		decryptButton = new JButton("Decrypt");
		decryptHandler = new DecryptHandler();
		decryptButton.addActionListener(decryptHandler);

		openFileButton = new JButton("Choose File ...");
		openFileHandler = new openFileHandler();
		openFileButton.addActionListener(openFileHandler);

		setTitle("DeekS Encryptor/ Decryptor");
		Container pane = getContentPane();
		pane.setLayout(new GridLayout(3, 2));

		// Add components to the pane in the order you want them to appear (left
		// to
		// right, top to bottom)
		pane.add(passwordLabel);
		pane.add(passwordTextBox);
		pane.add(openFileButton);
		pane.add(filePathTextField);
		pane.add(encryptButton);
		pane.add(decryptButton);

		setSize(WIDTH, HEIGHT);
		setVisible(true);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
	}

	private class EncryptHandler implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			try {
				String passKey = passwordTextBox.getText().toString().trim();
				passwordTextBox.setText("");
				String fileName = filePathTextField.getText().trim();

				String fileExtension = getFileExtension(fileName);
				FileInputStream fstream = new FileInputStream(fileName);

				// Get the Key
				byte[] key = (passKey).getBytes();
				MessageDigest sha = MessageDigest.getInstance("SHA-1");
				key = sha.digest(key);
				key = Arrays.copyOf(key, 16); // use only first 128 bit
				SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

				// Instantiate the cipher
				cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
				CipherInputStream cipherIn = new CipherInputStream(fstream,
						cipher);

				// Open dialog box and chose the location to save the encrypted
				// file
				int returnVal = fc.showSaveDialog(LithasaEncryptor.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					String saveName = file.getAbsolutePath();

					// Generate file extension.
					if (!saveName.contains(fileExtension))
						saveName += fileExtension;

					FileOutputStream fos = new FileOutputStream(new File(
							saveName));

					int i;
					while ((i = cipherIn.read()) != -1)
						fos.write(i);
					cipherIn.close();
					fos.close();
				}
			} catch (Exception ex) {

				// Do Nothing, if it no work, it no work
			}

		}
	}

	public class DecryptHandler implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			try {
				String passKey = passwordTextBox.getText().toString().trim();
				passwordTextBox.setText("");
				String fileName = filePathTextField.getText().trim();

				// Get the extension of the file.
				String fileExtension = getFileExtension(fileName);
				FileInputStream fstream = new FileInputStream(fileName);
				// Get the Key
				byte[] key = (passKey).getBytes();

				MessageDigest sha = MessageDigest.getInstance("SHA-1");
				key = sha.digest(key);
				key = Arrays.copyOf(key, 16); // use only first 128 bit
				SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

				// Instantiate the cipher
				cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

				CipherInputStream cipherIn = new CipherInputStream(fstream,
						cipher);

				// Open dialog box and choose the location to save the decrypted
				// file.
				int returnVal = fc.showSaveDialog(LithasaEncryptor.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					String saveName = file.getAbsolutePath();
					if (!saveName.contains(fileExtension))
						saveName += fileExtension;

					FileOutputStream fos = new FileOutputStream(new File(
							saveName));

					int i;
					while ((i = cipherIn.read()) != -1)
						fos.write(i);
					cipherIn.close();
					fos.close();
				}
			} catch (Exception ex) {
			}
		}
	}

	public class openFileHandler implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			try {
				int returnVal = fc.showOpenDialog(LithasaEncryptor.this);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					filePathTextField.setText(file.getAbsolutePath());
				}

			} catch (Exception ex) {
			}
		}
	}

	private String getFileExtension(String fileName) {
		// Handle the case where there is no extension, if file has less than 3
		// characters in its name, it has either no name (only an extension, for
		// example a '.c') or no extension
		if (fileName.length() < 3 || fileName.indexOf(".") == -1)
			return "";
		int index = fileName.lastIndexOf('.');
		String extension = fileName.substring(index);
		return extension;
	}

	public static void main(String[] args) {
		new LithasaEncryptor();
	}
}