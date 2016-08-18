//refer "AES Payloads" in burp app store
package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.awt.Component;
import java.io.PrintWriter;
import java.net.URLEncoder;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import java.awt.GridBagLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sun.glass.ui.TouchInputSupport;

import burp.CAESOperator_AES_128; //AES加解密算法的实现类
import burp.CUnicode; //unicode解码的实现类
import burp.IParameter;
import sun.awt.resources.awt;


public class BurpExtender implements IBurpExtender, IHttpListener,ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
    private JPanel panel;
    public final String TAB_NAME = "AES Config";
    
    private JCheckBox forScanner,forIntruder,forRepeater,forProxy;
    private JCheckBox decrpytResponse,showClearText;
    
    private JLabel hexFormat;
    private JLabel stringFormat;
    private JTextField hexString;
    private JTextField textString;
    private JButton hexButton;
    
    private JTextField parameterAESkey;
    private JTextField parameterAESIV;
    private JLabel lblDescription;
    private JComboBox comboAESMode;
    private JLabel lbl3;
    private JCheckBox chckbxNewCheckBox;
    private JCheckBox chckbxBaseEncode;
    private JPanel panel_1;
    private JPanel panel_0;


    private JButton btnNewButton;
    private JTextArea textAreaPlaintext;
    private JTextArea textAreaCiphertext;
    private JButton btnNewButton_1;
    private JLabel lblPlaintext;
    private JLabel lblCiphertext;
    //public IntruderPayloadProcessor payloadEncryptor;
    //public IntruderPayloadProcessor payloadDecryptor;
    
    private String AESkey; //these parameters are get from GUI use to encrypt or decrypt
    private String AESIV;
    private String AESMode;
    private boolean BaseEncode;
    private String Plaintext;
    private String Chiphertext;
		

    
    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	stdout = new PrintWriter(callbacks.getStdout(), true);
    	//PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true); 这种写法是定义变量和实例化，这里的变量就是新的变量而不是之前class中的全局变量了。
    	stdout.println("Para Encrypter v1.0 by bit4");
    	//System.out.println("test"); 不会输出到burp的
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Para Encrypter v1.0 by bit4"); //插件名称
        callbacks.registerHttpListener(this); //如果没有注册，下面的processHttpMessage方法是不会生效的。处理请求和响应包的插件，这个应该是必要的
        addMenuTab();
    }

    @Override
    public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo)
    {
		List<String> paraWhiteList = new ArrayList<String>(); //参数白名单，白名单中的参数值不进行加密计算
		paraWhiteList.add("android");
		
		
    	if (toolFlag == (toolFlag&checkEnabledFor())){ //不同的toolflag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
    		if (messageIsRequest){ //对请求包进行处理
    			
    			//获取各种参数和消息体的方法罗列如下，无非三种，body，header，paramater
    			IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo); //对消息体进行解析 
    			//the method of get header
    			List<String> headers = analyzeRequest.getHeaders(); //获取http请求头的信息，返回可以看作是一个python中的列表，java中是叫泛型什么的，还没弄清楚
    			//the method of get body
    			int bodyOffset = analyzeRequest.getBodyOffset();
    			byte[] byte_Request = messageInfo.getRequest();
    			String request = new String(byte_Request); //byte[] to String
                String body = request.substring(bodyOffset);
                byte[] byte_body = body.getBytes();  //String to byte[]
    			//the method of get parameter
                List<IParameter> paraList = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
                //如果在url中的参数的值是 xxx=json格式的字符串 这种形式的时候，getParameters应该是无法获取到最底层的键值对的。
                //获取各种参数和消息体部分的集合 
                getPara();//获取配置面板上的各项值。
                
                //判断一个请求是否是文件上传的请求。
    			boolean isFileUploadRequest =false;
    			for (String header : headers){
    				//stdout.println(header);
    				if (header.toLowerCase().indexOf("content-type")!=-1 && header.toLowerCase().indexOf("boundary")!=-1){//通过http头中的内容判断这个请求是否是文件上传的请求
    					isFileUploadRequest = true;
    				}
    			}
    			
    			if (isFileUploadRequest == false){ //对文件上传的请求，对其中的参数不做加密处理
	    			byte[] new_Request = messageInfo.getRequest();
	    			for (IParameter para : paraList){// 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。
	    				if ((para.getType() == 0 || para.getType() == 1) && !paraWhiteList.contains(para.getName())){ 
	    					//getTpe()就是来判断参数是在那个位置的，cookie中的参数是不需要进行加密处理的。还要排除白名单中的参数。
		    				//这里要注意的是，参数的类型共6种，如果body中的参数是json或者xml格式，需要单独判断。
	    					String key = para.getName(); //获取参数的名称
		    				String value = para.getValue(); //获取参数的值
		    				//stdout.println(key+":"+value);
		    				
		    				String aesvalue;
		    				try {
								aesvalue = CAES.encrypt(AESkey,AESIV,BaseEncode,AESMode,Plaintext);
								aesvalue = URLEncoder.encode(aesvalue); //还要进行URL编码，否则会出现= 等特殊字符导致参数判断异常
			    				stdout.println(key+":"+value+":"+aesvalue); //输出到extender的UI窗口，可以让使用者有一些判断
			    				//更新包的方法集合
			    				//更新参数
			    				IParameter newPara = helpers.buildParameter(key, aesvalue, para.getType()); //构造新的参数,如果参数是PARAM_JSON类型，这个方法是不适用的
			    				//IParameter newPara = helpers.buildParameter(key, aesvalue, PARAM_BODY); //要使用这个PARAM_BODY 是不是需要先实例化IParameter类。
			    				new_Request = helpers.updateParameter(new_Request, newPara); //构造新的请求包
			    				// new_Request = helpers.buildHttpMessage(headers, byte_body); //如果修改了header或者数修改了body，而不是通过updateParameter，使用这个方法。
							} catch (Exception e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} //对value值进行加密
		    				
	    				}
	    			}
	    			messageInfo.setRequest(new_Request);//设置最终新的请求包
    			}
    			/* to verify the updated result
    			for (IParameter para : helpers.analyzeRequest(messageInfo).getParameters()){
    				stdout.println(para.getValue());
    			}
    			*/		
    		}
    		
    		else{
    			if(this.decrpytResponse.isSelected()){
	    			//处理返回，响应包
	    			IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse()); //getResponse获得的是字节序列
	    			List<String> header = analyzedResponse.getHeaders();
	    			short statusCode = analyzedResponse.getStatusCode();
	    			int bodyOffset = analyzedResponse.getBodyOffset();
	    			if (statusCode==200){
	    				try{
		    				CAESOperator_AES_128 aes = new CAESOperator_AES_128();
		    				String resp = new String(messageInfo.getResponse());
		                    String body = resp.substring(bodyOffset);
		                    String deBody= CAES.decrypt(AESkey,AESIV,BaseEncode,AESMode,body);
		                    deBody = deBody.replace("\"", "\\\"");
		                    String UnicodeBody = (new CUnicode()).unicodeDecode(deBody);
		                    String newBody;
		                    if(showClearText.isSelected()){
		                    	 newBody = UnicodeBody;
		                    }
		                    else {
		                    	 newBody = body +"\r\n" +UnicodeBody; //将新的解密后的body附到旧的body后面
							}
		                    byte[] bodybyte = newBody.getBytes();
		                    //更新包的方法二buildHttpMessage
		                    messageInfo.setResponse(helpers.buildHttpMessage(header, bodybyte));
	    				}catch(Exception e){
	    					stdout.println(e);
	    				}
	    			}
    			}
    			
    		}	    		
    	}
    		
    }
    
    
    
    public void buildUI(){
       // Create configuration Panel
    	this.panel = new JPanel();
        GridBagLayout gbl_panel = new GridBagLayout();
        gbl_panel.columnWidths = new int[] { 139, 400, 0 };
        gbl_panel.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0 }; //  此字段保持对行最小高度的重写。
        gbl_panel.columnWeights = new double[] { 1.0D, 1.0D, Double.MIN_VALUE }; //     此字段保持对列最小宽度的重写
        gbl_panel.rowWeights = new double[] { 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 1.0D, Double.MIN_VALUE }; //     此字段保持对行权重的重写。
        this.panel.setLayout(gbl_panel);
        
        this.lblDescription = new JLabel("<html><b>Para Encrypter v1.0 by bit4</b><br>https://github.com/bit4woo.<br></html>");
        this.lblDescription.setHorizontalAlignment(2);
        this.lblDescription.setVerticalAlignment(1);
        GridBagConstraints gbc_lblDescription = new GridBagConstraints();
        gbc_lblDescription.fill = 2; //填充方式
        gbc_lblDescription.insets = new Insets(0, 0, 5, 0); //设置间隔
        gbc_lblDescription.gridx = 0; //当把gridx值设置为GridBagConstriants.RELETIVE时，所添加的组件将被放置在前一个组件的右侧
        gbc_lblDescription.gridy = 0; //同理，对gridy 值设置为GridBagConstraints.RELETIVE时，所添加的组件将被放置在前一个组件的下方
        this.panel.add(this.lblDescription, gbc_lblDescription);
        
        this.forScanner = new JCheckBox("Enable For Scanner");
        this.forScanner.setSelected(true);
        this.forIntruder = new JCheckBox("Enable For Intruder");
        this.forIntruder.setSelected(true);
        this.forRepeater = new JCheckBox("Enable For Repeater");
        this.forRepeater.setSelected(true);
        this.forProxy = new JCheckBox("Enable For Proxy");
        this.forProxy.setSelected(true);
        
        this.decrpytResponse = new JCheckBox("Decrypt Response");
        this.decrpytResponse.setSelected(true);
        this.showClearText = new JCheckBox("show decrypted clear content in response only");
        this.showClearText.setSelected(false);
        
        this.panel.add(forScanner);
        this.panel.add(forIntruder);
        this.panel.add(forRepeater);
        this.panel.add(forProxy);
        this.panel.add(decrpytResponse);
        this.panel.add(showClearText);
        
        
        /////实现hex和string的转换
        this.panel_0 = new JPanel();
        GridBagConstraints gbc_panel_0 = new GridBagConstraints();
        gbc_panel_0.gridwidth = 2;
        gbc_panel_0.insets = new Insets(0, 0, 0, 5);
        gbc_panel_0.fill = 1;
        gbc_panel_0.gridx = 0;
        gbc_panel_0.gridy = 1;
        this.panel.add(this.panel_0, gbc_panel_0);
        GridBagLayout gbl_panel_0 = new GridBagLayout();
//        gbl_panel_0.columnWidths = new int[] { 0, 0, 0, 0 };
//        gbl_panel_0.rowHeights = new int[] { 0, 0, 0, 0 };
//        gbl_panel_0.columnWeights = new double[] { 1.0D, 0.0D, 1.0D, Double.MIN_VALUE };
//        gbl_panel_0.rowWeights = new double[] { 0.0D, 0.0D, 1.0D, Double.MIN_VALUE };
        this.panel_0.setLayout(gbl_panel_0);
        
        this.hexFormat = new JLabel("hexFormat");
        this.hexFormat.setHorizontalAlignment(SwingConstants.LEFT);//对齐方式
        GridBagConstraints gbc_hexFormat = new GridBagConstraints();
        gbc_hexFormat.insets = new Insets(0, 0, 5, 5);
        gbc_hexFormat.gridx = 0;
        gbc_hexFormat.gridy = 0;
        this.panel_0.add(this.hexFormat, gbc_hexFormat);
        
        
        this.stringFormat = new JLabel("stringFormat");
        this.stringFormat.setHorizontalAlignment(4);
        GridBagConstraints gbc_stringFormat = new GridBagConstraints();
        gbc_stringFormat.insets = new Insets(0, 0, 5, 0);
        gbc_stringFormat.gridx = 2;
        gbc_stringFormat.gridy = 0;
        this.panel_0.add(this.stringFormat, gbc_stringFormat);
        
        this.hexString = new JTextField();
        GridBagConstraints gbc_hexString = new GridBagConstraints();
        gbc_hexString.gridheight = 2;
        gbc_hexString.insets = new Insets(0, 0, 0, 5);
        gbc_hexString.fill = 2;
        gbc_hexString.gridx = 0;
        gbc_hexString.gridy = 1;
        this.panel_0.add(this.hexString, gbc_hexString);
        this.hexString.setColumns(40);//成功控制了文本框的宽度
        
        this.hexButton = new JButton("->");
        this.hexButton.addActionListener(new ActionListener()
        {
          public void actionPerformed(ActionEvent arg0)
          {
            try
            {
              getPara();
              BurpExtender.this.textAreaCiphertext.setText(CHexString2String.hexStringToString(BurpExtender.this.hexString.getText()));
            }
            catch (Exception e)
            {
              BurpExtender.this.callbacks.issueAlert(e.toString());
            }
          }
        });
        GridBagConstraints gbc_hexButton = new GridBagConstraints();
        gbc_hexButton.insets = new Insets(0, 0, 5, 5);
        gbc_hexButton.gridx = 1;
        gbc_hexButton.gridy = 1;
        this.panel_0.add(this.hexButton, gbc_hexButton);
        
        this.textString = new JTextField();
        GridBagConstraints gbc_textString = new GridBagConstraints();
        gbc_textString.gridheight = 2;
        gbc_textString.fill = 2;
        gbc_textString.gridx = 2;
        gbc_textString.gridy = 1;
        this.panel_0.add(this.textString, gbc_textString);
        this.textString.setColumns(40);
        
//        this.btnNewButton_1 = new JButton("<-");
//        this.btnNewButton_1.addActionListener(new ActionListener()
//        {
//          public void actionPerformed(ActionEvent arg0)
//          {
//            try
//            {
//              getPara();
//              BurpExtender.this.textAreaPlaintext.setText(CAES.decrypt(AESkey,AESIV,BaseEncode,AESMode,Chiphertext));
//            }
//            catch (Exception e)
//            {
//              BurpExtender.this.callbacks.issueAlert(e.toString());
//            }
//          }
//        });
//        this.btnNewButton_1.setVerticalAlignment(1);
//        GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
//        gbc_btnNewButton_1.anchor = 11;
//        gbc_btnNewButton_1.insets = new Insets(0, 0, 0, 5);
//        gbc_btnNewButton_1.gridx = 1;
//        gbc_btnNewButton_1.gridy = 2;
//        this.panel_0.add(this.btnNewButton_1, gbc_btnNewButton_1);
        //////////实现hex 和string的转换
        
        
        JLabel lbl1 = new JLabel("AES key String:");
        lbl1.setHorizontalAlignment(4);
        GridBagConstraints gbc_lbl1 = new GridBagConstraints();
        gbc_lbl1.anchor = 13;
        gbc_lbl1.insets = new Insets(0, 0, 5, 5);
        gbc_lbl1.gridx = 0;
        gbc_lbl1.gridy = 2;
        this.panel.add(lbl1, gbc_lbl1);
        
        this.parameterAESkey = new JTextField();
        this.parameterAESkey.setText("bit4@MZSEC.2016.");
        GridBagConstraints gbc_parameterAESkey = new GridBagConstraints();
        gbc_parameterAESkey.insets = new Insets(0, 0, 5, 0);
        gbc_parameterAESkey.fill = 2;
        gbc_parameterAESkey.gridx = 1;
        gbc_parameterAESkey.gridy = 2;
        this.panel.add(this.parameterAESkey, gbc_parameterAESkey);
        this.parameterAESkey.setColumns(10);
        
        JLabel lbl2 = new JLabel("IV String:");
        lbl2.setHorizontalAlignment(4);
        GridBagConstraints gbc_lbl2 = new GridBagConstraints();
        gbc_lbl2.insets = new Insets(0, 0, 5, 5);
        gbc_lbl2.anchor = 13;
        gbc_lbl2.gridx = 0;
        gbc_lbl2.gridy = 3;
        this.panel.add(lbl2, gbc_lbl2);
        
        this.parameterAESIV = new JTextField();
        this.parameterAESIV.setText("0123456789ABCDEF");
        this.parameterAESIV.setColumns(10);
        GridBagConstraints gbc_parameterAESIV = new GridBagConstraints();
        gbc_parameterAESIV.insets = new Insets(0, 0, 5, 0);
        gbc_parameterAESIV.fill = 2;
        gbc_parameterAESIV.gridx = 1;
        gbc_parameterAESIV.gridy = 3;
        this.panel.add(this.parameterAESIV, gbc_parameterAESIV);
        
//        this.chckbxNewCheckBox = new JCheckBox("IV block in Ciphertext (not yet working)");
//        this.chckbxNewCheckBox.setEnabled(false);
//        GridBagConstraints gbc_chckbxNewCheckBox = new GridBagConstraints();
//        gbc_chckbxNewCheckBox.fill = 2;
//        gbc_chckbxNewCheckBox.insets = new Insets(0, 0, 5, 0);
//        gbc_chckbxNewCheckBox.gridx = 0;
//        gbc_chckbxNewCheckBox.gridy = 4;
//        this.panel.add(this.chckbxNewCheckBox, gbc_chckbxNewCheckBox);
        
        this.chckbxBaseEncode = new JCheckBox("Base 64 Decode/Encode");
        this.chckbxBaseEncode.setSelected(true);
        GridBagConstraints gbc_chckbxBaseEncode = new GridBagConstraints();
        gbc_chckbxBaseEncode.fill = 2;
        gbc_chckbxBaseEncode.insets = new Insets(0, 0, 5, 0);
        gbc_chckbxBaseEncode.gridx = 1;
        gbc_chckbxBaseEncode.gridy = 4;
        this.panel.add(this.chckbxBaseEncode, gbc_chckbxBaseEncode);
        
        this.lbl3 = new JLabel("AES Mode:");
        this.lbl3.setHorizontalAlignment(4);
        GridBagConstraints gbc_lbl3 = new GridBagConstraints();
        gbc_lbl3.insets = new Insets(0, 0, 5, 5);
        gbc_lbl3.anchor = 13;
        gbc_lbl3.gridx = 0;
        gbc_lbl3.gridy = 5;
        this.panel.add(this.lbl3, gbc_lbl3);
        
        this.comboAESMode = new JComboBox();//下拉菜单
        this.comboAESMode.addPropertyChangeListener(new PropertyChangeListener()
        {
          public void propertyChange(PropertyChangeEvent arg0)
          {
            String cmode = (String)BurpExtender.this.comboAESMode.getSelectedItem();
            if (cmode.contains("CBC")) {
              BurpExtender.this.parameterAESIV.setEditable(true);
            } else {
              BurpExtender.this.parameterAESIV.setEditable(false);
            }
          }
        });
        this.comboAESMode.setModel(new DefaultComboBoxModel(new String[] { "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding" }));
        this.comboAESMode.setSelectedIndex(1);
        GridBagConstraints gbc_comboAESMode = new GridBagConstraints();
        gbc_comboAESMode.insets = new Insets(0, 0, 5, 0);
        gbc_comboAESMode.fill = 2;
        gbc_comboAESMode.gridx = 1;
        gbc_comboAESMode.gridy = 5;
        this.panel.add(this.comboAESMode, gbc_comboAESMode);
        
        ///文本区域的一个单独panel
        this.panel_1 = new JPanel();
        GridBagConstraints gbc_panel_1 = new GridBagConstraints();
        gbc_panel_1.gridwidth = 3;
        gbc_panel_1.insets = new Insets(0, 0, 0, 5);
        gbc_panel_1.fill = 1;
        gbc_panel_1.gridx = 0;
        gbc_panel_1.gridy = 6;
        this.panel.add(this.panel_1, gbc_panel_1);
        GridBagLayout gbl_panel_1 = new GridBagLayout();
        gbl_panel_1.columnWidths = new int[] { 0, 0, 0, 0 };
        gbl_panel_1.rowHeights = new int[] { 0, 0, 0, 0 };
        gbl_panel_1.columnWeights = new double[] { 1.0D, 0.0D, 1.0D, Double.MIN_VALUE };
        gbl_panel_1.rowWeights = new double[] { 0.0D, 0.0D, 1.0D, Double.MIN_VALUE };
        this.panel_1.setLayout(gbl_panel_1);
        
        this.lblPlaintext = new JLabel("Plaintext");
        this.lblPlaintext.setHorizontalAlignment(4);
        GridBagConstraints gbc_lblPlaintext = new GridBagConstraints();
        gbc_lblPlaintext.insets = new Insets(0, 0, 5, 5);
        gbc_lblPlaintext.gridx = 0;
        gbc_lblPlaintext.gridy = 0;
        this.panel_1.add(this.lblPlaintext, gbc_lblPlaintext);
        
        this.lblCiphertext = new JLabel("Ciphertext");
        this.lblCiphertext.setHorizontalAlignment(4);
        GridBagConstraints gbc_lblCiphertext = new GridBagConstraints();
        gbc_lblCiphertext.insets = new Insets(0, 0, 5, 0);
        gbc_lblCiphertext.gridx = 2;
        gbc_lblCiphertext.gridy = 0;
        this.panel_1.add(this.lblCiphertext, gbc_lblCiphertext);
        
        this.textAreaPlaintext = new JTextArea();
        this.textAreaPlaintext.setLineWrap(true);
        GridBagConstraints gbc_textAreaPlaintext = new GridBagConstraints();
        gbc_textAreaPlaintext.gridheight = 2;
        gbc_textAreaPlaintext.insets = new Insets(0, 0, 0, 5);
        gbc_textAreaPlaintext.fill = 1;
        gbc_textAreaPlaintext.gridx = 0;
        gbc_textAreaPlaintext.gridy = 1;
        this.panel_1.add(this.textAreaPlaintext, gbc_textAreaPlaintext);
        
        this.btnNewButton = new JButton("Encrypt ->");
        this.btnNewButton.addActionListener(new ActionListener()
        {
          public void actionPerformed(ActionEvent arg0)
          {
            try
            {
              getPara();
              BurpExtender.this.textAreaCiphertext.setText(CAES.encrypt(AESkey,AESIV,BaseEncode,AESMode,Plaintext));
            }
            catch (Exception e)
            {
              BurpExtender.this.callbacks.issueAlert(e.toString());
            }
          }
        });
        GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
        gbc_btnNewButton.insets = new Insets(0, 0, 5, 5);
        gbc_btnNewButton.gridx = 1;
        gbc_btnNewButton.gridy = 1;
        this.panel_1.add(this.btnNewButton, gbc_btnNewButton);
        
        this.textAreaCiphertext = new JTextArea();
        this.textAreaCiphertext.setLineWrap(true);
        GridBagConstraints gbc_textAreaCiphertext = new GridBagConstraints();
        gbc_textAreaCiphertext.gridheight = 2;
        gbc_textAreaCiphertext.fill = 1;
        gbc_textAreaCiphertext.gridx = 2;
        gbc_textAreaCiphertext.gridy = 1;
        this.panel_1.add(this.textAreaCiphertext, gbc_textAreaCiphertext);
        
        this.btnNewButton_1 = new JButton("<- Decrypt");
        this.btnNewButton_1.addActionListener(new ActionListener()
        {
          public void actionPerformed(ActionEvent arg0)
          {
            try
            {
              getPara();
              BurpExtender.this.textAreaPlaintext.setText(CAES.decrypt(AESkey,AESIV,BaseEncode,AESMode,Chiphertext));
            }
            catch (Exception e)
            {
              BurpExtender.this.callbacks.issueAlert(e.toString());
            }
          }
        });
        this.btnNewButton_1.setVerticalAlignment(1);
        GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
        gbc_btnNewButton_1.anchor = 11;
        gbc_btnNewButton_1.insets = new Insets(0, 0, 0, 5);
        gbc_btnNewButton_1.gridx = 1;
        gbc_btnNewButton_1.gridy = 2;
        this.panel_1.add(this.btnNewButton_1, gbc_btnNewButton_1);
    }
    //文本框部分

    public void addMenuTab()
    {
      SwingUtilities.invokeLater(new Runnable()
      {
        public void run()
        {
          BurpExtender.this.buildUI();
          BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
        }
      });
    }
	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return ("Para Encrypter");
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this.panel;
	}

	public void getPara(){
		//get values in AES config panel
		this.AESkey = this.parameterAESkey.getText();
		this.AESIV = this.parameterAESIV.getText();
		this.BaseEncode = this.chckbxBaseEncode.isSelected();
		this.AESMode = (String)this.comboAESMode.getSelectedItem();
		this.Plaintext = this.textAreaPlaintext.getText();
		this.Chiphertext = this.textAreaCiphertext.getText();
	}
	
	public int checkEnabledFor(){
		//get values that should enable this extender for which Component.
		int status = 0;
		if (forIntruder.isSelected()){
			status +=32;
		}
		if(forProxy.isSelected()){
			status += 4;
		}
		if(forRepeater.isSelected()){
			status += 64;
		}
		if(forScanner.isSelected()){
			status += 16;
		}
		return status;
	}
	
}