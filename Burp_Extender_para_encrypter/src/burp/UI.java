package burp;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import java.awt.GridLayout;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;


import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.ListSelectionModel;
import javax.swing.JButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.JTabbedPane;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Dimension;
import javax.swing.JTextArea;
import net.miginfocom.swing.MigLayout;
import java.awt.ComponentOrientation;
import java.awt.Cursor;

import javax.swing.JSplitPane;
import java.awt.event.MouseMotionAdapter;
import java.awt.event.MouseEvent;

public class UI extends JFrame {

	private JPanel contentPane;
	private JTextField textFieldDomain;
	private JTable table;
	private JTextField addhere;
	private JTextField txtAESKey;
	private JTextField txtIVString;
	private JCheckBox chckbxProxy;
	private JCheckBox chckbxScanner;
	private JCheckBox chckbxIntruder;
	private JCheckBox chckbxRepeater;
	private JCheckBox decryptResponse;
	private JCheckBox chckbxShowDecryptedOnly;
	private JTextArea textPlain;
	private JTextArea textChiper;
	private JCheckBox checkBoxBase64;
	private JComboBox comboBoxAESMode;
	private JTabbedPane tabbedPane_Center;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					UI frame = new UI();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public UI() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1015, 478);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(5, 5));
		setContentPane(contentPane);
		
		JPanel panel_North = new JPanel();
		contentPane.add(panel_North, BorderLayout.NORTH);
		panel_North.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel_North.add(panel_3);
		GridBagLayout gbl_panel_3 = new GridBagLayout();
		gbl_panel_3.columnWidths = new int[]{161, 161, 161, 161, 161, 0};
		gbl_panel_3.rowHeights = new int[]{23, 23, 0};
		gbl_panel_3.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panel_3.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel_3.setLayout(gbl_panel_3);
		
		JLabel enableFor = new JLabel("Enable For :");
		GridBagConstraints gbc_enableFor = new GridBagConstraints();
		gbc_enableFor.fill = GridBagConstraints.BOTH;
		gbc_enableFor.insets = new Insets(0, 0, 5, 5);
		gbc_enableFor.gridx = 0;
		gbc_enableFor.gridy = 0;
		panel_3.add(enableFor, gbc_enableFor);
		
		chckbxProxy = new JCheckBox("Proxy");
		GridBagConstraints gbc_chckbxProxy = new GridBagConstraints();
		gbc_chckbxProxy.fill = GridBagConstraints.BOTH;
		gbc_chckbxProxy.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxProxy.gridx = 1;
		gbc_chckbxProxy.gridy = 0;
		panel_3.add(chckbxProxy, gbc_chckbxProxy);
		
		chckbxScanner = new JCheckBox("Scanner");
		GridBagConstraints gbc_chckbxScanner = new GridBagConstraints();
		gbc_chckbxScanner.fill = GridBagConstraints.BOTH;
		gbc_chckbxScanner.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxScanner.gridx = 2;
		gbc_chckbxScanner.gridy = 0;
		panel_3.add(chckbxScanner, gbc_chckbxScanner);
		
		chckbxIntruder = new JCheckBox("Intruder");
		GridBagConstraints gbc_chckbxIntruder = new GridBagConstraints();
		gbc_chckbxIntruder.fill = GridBagConstraints.BOTH;
		gbc_chckbxIntruder.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIntruder.gridx = 3;
		gbc_chckbxIntruder.gridy = 0;
		panel_3.add(chckbxIntruder, gbc_chckbxIntruder);
		
		chckbxRepeater = new JCheckBox("Repeater");
		chckbxRepeater.setSelected(true);
		GridBagConstraints gbc_chckbxRepeater = new GridBagConstraints();
		gbc_chckbxRepeater.fill = GridBagConstraints.BOTH;
		gbc_chckbxRepeater.insets = new Insets(0, 0, 5, 0);
		gbc_chckbxRepeater.gridx = 4;
		gbc_chckbxRepeater.gridy = 0;
		panel_3.add(chckbxRepeater, gbc_chckbxRepeater);
		
		JLabel dealResponse = new JLabel("About Response :");
		GridBagConstraints gbc_dealResponse = new GridBagConstraints();
		gbc_dealResponse.fill = GridBagConstraints.BOTH;
		gbc_dealResponse.insets = new Insets(0, 0, 0, 5);
		gbc_dealResponse.gridx = 0;
		gbc_dealResponse.gridy = 1;
		panel_3.add(dealResponse, gbc_dealResponse);
		
		decryptResponse = new JCheckBox("Decrypt Response");
		GridBagConstraints gbc_decryptResponse = new GridBagConstraints();
		gbc_decryptResponse.fill = GridBagConstraints.BOTH;
		gbc_decryptResponse.insets = new Insets(0, 0, 0, 5);
		gbc_decryptResponse.gridx = 1;
		gbc_decryptResponse.gridy = 1;
		panel_3.add(decryptResponse, gbc_decryptResponse);
		
		chckbxShowDecryptedOnly = new JCheckBox("Show Decrypted Content Only");
		GridBagConstraints gbc_chckbxShowDecryptedOnly = new GridBagConstraints();
		gbc_chckbxShowDecryptedOnly.fill = GridBagConstraints.BOTH;
		gbc_chckbxShowDecryptedOnly.insets = new Insets(0, 0, 0, 5);
		gbc_chckbxShowDecryptedOnly.gridx = 2;
		gbc_chckbxShowDecryptedOnly.gridy = 1;
		panel_3.add(chckbxShowDecryptedOnly, gbc_chckbxShowDecryptedOnly);
		
		JPanel panel_South = new JPanel();
		panel_South.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_South, BorderLayout.SOUTH);
		panel_South.setLayout(new BoxLayout(panel_South, BoxLayout.X_AXIS));
		
		JLabel lblNewLabel = new JLabel("Para Encrypter v1.0 by bit4    https://github.com/bit4woo");
		panel_South.add(lblNewLabel);
		lblNewLabel.setHorizontalAlignment(SwingConstants.LEFT);
		
		JPanel panel_East = new JPanel();
		contentPane.add(panel_East, BorderLayout.EAST);
		panel_East.setLayout(new BorderLayout(0, 0));
		
		textPlain = new JTextArea(20,20);
		textPlain.setLineWrap(true);
		panel_East.add(textPlain, BorderLayout.WEST);
		
		JPanel panel_9 = new JPanel();
		panel_East.add(panel_9, BorderLayout.CENTER);
		GridBagLayout gbl_panel_9 = new GridBagLayout();
		gbl_panel_9.columnWidths = new int[]{93, 0};
		gbl_panel_9.rowHeights = new int[]{23, 0, 0};
		gbl_panel_9.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panel_9.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel_9.setLayout(gbl_panel_9);
		
		JButton btnNewButton_1 = new JButton("Encrypt ->");
		GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
		gbc_btnNewButton_1.insets = new Insets(0, 0, 5, 0);
		gbc_btnNewButton_1.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnNewButton_1.gridx = 0;
		gbc_btnNewButton_1.gridy = 0;
		panel_9.add(btnNewButton_1, gbc_btnNewButton_1);
		
		JButton btnNewButton_2 = new JButton("<- Decrypt");
		GridBagConstraints gbc_btnNewButton_2 = new GridBagConstraints();
		gbc_btnNewButton_2.gridx = 0;
		gbc_btnNewButton_2.gridy = 1;
		panel_9.add(btnNewButton_2, gbc_btnNewButton_2);
		
		textChiper = new JTextArea(20,20);
		textChiper.setLineWrap(true);
		panel_East.add(textChiper, BorderLayout.EAST);
		
		JPanel panel_West = new JPanel();
		panel_West.setPreferredSize(new Dimension(500, 200));
		panel_West.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_West, BorderLayout.WEST);
		panel_West.setLayout(new BorderLayout(0, 0));
		
		JPanel panel = new JPanel();
		panel_West.add(panel, BorderLayout.NORTH);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblDomainName = new JLabel("Domain :");
		panel.add(lblDomainName);
		
		textFieldDomain = new JTextField();
		panel.add(textFieldDomain);
		textFieldDomain.setColumns(10);
		
		JLabel lblParaIncluded = new JLabel("Parameters That Need To Encrypt :");
		panel.add(lblParaIncluded);
		
		table = new JTable();
//		table.setColumnSelectionAllowed(true);
//		table.setCellSelectionEnabled(true);
		table.getTableHeader().setResizingAllowed(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		table.setModel(new DefaultTableModel(
			new Object[][] {
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
				{null, null},
			},
			new String[] {
				"key", "value"
			}
		));
		panel_West.add(table, BorderLayout.CENTER);
		
		JPanel panel_1 = new JPanel();
		panel_West.add(panel_1, BorderLayout.EAST);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{69, 0};
		gbl_panel_1.rowHeights = new int[]{23, 0, 0};
		gbl_panel_1.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		JButton btnRemove = new JButton("Remove");
		btnRemove.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
			}
		});
		GridBagConstraints gbc_btnRemove = new GridBagConstraints();
		gbc_btnRemove.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemove.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnRemove.gridx = 0;
		gbc_btnRemove.gridy = 0;
		panel_1.add(btnRemove, gbc_btnRemove);
		
		JPanel panel_2 = new JPanel();
		panel_West.add(panel_2, BorderLayout.SOUTH);
		panel_2.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		addhere = new JTextField();
		panel_2.add(addhere);
		addhere.setColumns(20);
		
		JButton btnNewButton = new JButton("Add");
		panel_2.add(btnNewButton);
		
		tabbedPane_Center = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane_Center.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		tabbedPane_Center.setSize(new Dimension(20, 20));
		tabbedPane_Center.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
		tabbedPane_Center.setMinimumSize(new Dimension(20, 20));
		contentPane.add(tabbedPane_Center, BorderLayout.CENTER);
		
		
		JPanel panel_4 = new JPanel();
		panel_4.setMinimumSize(new Dimension(20, 20));
		tabbedPane_Center.addTab("AES", null, panel_4, null);
		GridBagLayout gbl_panel_4 = new GridBagLayout();
		gbl_panel_4.columnWidths = new int[]{96, 178, 0};
		gbl_panel_4.rowHeights = new int[]{21, 21, 23, 21, 0};
		gbl_panel_4.columnWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		gbl_panel_4.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_4.setLayout(gbl_panel_4);
		
		JLabel lblAESkey = new JLabel("AES Key String :");
		GridBagConstraints gbc_lblAESkey = new GridBagConstraints();
		gbc_lblAESkey.anchor = GridBagConstraints.WEST;
		gbc_lblAESkey.insets = new Insets(0, 0, 5, 5);
		gbc_lblAESkey.gridx = 0;
		gbc_lblAESkey.gridy = 0;
		panel_4.add(lblAESkey, gbc_lblAESkey);
		
		txtAESKey = new JTextField();
		txtAESKey.setText("bit4@MZSEC.2016.");
		GridBagConstraints gbc_txtAESKey = new GridBagConstraints();
		gbc_txtAESKey.anchor = GridBagConstraints.NORTH;
		gbc_txtAESKey.fill = GridBagConstraints.HORIZONTAL;
		gbc_txtAESKey.insets = new Insets(0, 0, 5, 0);
		gbc_txtAESKey.gridx = 1;
		gbc_txtAESKey.gridy = 0;
		panel_4.add(txtAESKey, gbc_txtAESKey);
		txtAESKey.setColumns(40);
		
		JLabel label = new JLabel("AES IV String :");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.anchor = GridBagConstraints.WEST;
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 0;
		gbc_label.gridy = 1;
		panel_4.add(label, gbc_label);
		
		txtIVString = new JTextField();
		txtIVString.setText("0123456789ABCDEF");
		txtIVString.setColumns(20);
		GridBagConstraints gbc_txtIVString = new GridBagConstraints();
		gbc_txtIVString.anchor = GridBagConstraints.NORTH;
		gbc_txtIVString.fill = GridBagConstraints.HORIZONTAL;
		gbc_txtIVString.insets = new Insets(0, 0, 5, 0);
		gbc_txtIVString.gridx = 1;
		gbc_txtIVString.gridy = 1;
		panel_4.add(txtIVString, gbc_txtIVString);
		
		checkBoxBase64 = new JCheckBox("Base64 Decode/Encode");
		checkBoxBase64.setSelected(true);
		GridBagConstraints gbc_checkBoxBase64 = new GridBagConstraints();
		gbc_checkBoxBase64.anchor = GridBagConstraints.NORTHWEST;
		gbc_checkBoxBase64.insets = new Insets(0, 0, 5, 0);
		gbc_checkBoxBase64.gridx = 1;
		gbc_checkBoxBase64.gridy = 2;
		panel_4.add(checkBoxBase64, gbc_checkBoxBase64);
		
		JLabel lblAesMode = new JLabel("AES Mode :");
		GridBagConstraints gbc_lblAesMode = new GridBagConstraints();
		gbc_lblAesMode.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblAesMode.insets = new Insets(0, 0, 0, 5);
		gbc_lblAesMode.gridx = 0;
		gbc_lblAesMode.gridy = 3;
		panel_4.add(lblAesMode, gbc_lblAesMode);
		
		comboBoxAESMode = new JComboBox();
		comboBoxAESMode.setModel(new DefaultComboBoxModel(new String[] {"AES/CBC/PKCS5Padding","AES/ECB/PKCS5Padding","AES/CBC/NoPadding","AES/ECB/NoPadding"}));
		GridBagConstraints gbc_comboBoxAESMode = new GridBagConstraints();
		gbc_comboBoxAESMode.anchor = GridBagConstraints.NORTH;
		gbc_comboBoxAESMode.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBoxAESMode.gridx = 1;
		gbc_comboBoxAESMode.gridy = 3;
		panel_4.add(comboBoxAESMode, gbc_comboBoxAESMode);
		

		
		JPanel panel_5 = new JPanel();
		tabbedPane_Center.addTab("Base64", null, panel_5, null);
		
		JLabel lblSwitchToThis = new JLabel("Switch to this tab to use Base64 encryopt and decrypt");
		panel_5.add(lblSwitchToThis);
		
		JPanel panel_6 = new JPanel();
		tabbedPane_Center.addTab("RSA", null, panel_6, null);
		
		JPanel panel_7 = new JPanel();
		tabbedPane_Center.addTab("DES", null, panel_7, null);
	}

}
