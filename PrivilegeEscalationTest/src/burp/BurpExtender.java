package burp;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import javax.swing.table.DefaultTableModel;


public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private String request;
    private JPanel MainPane;
    private JButton Header_add,Header_remv,Get_add,Get_remv,Post_add,Post_remv,contL_add,contL_remv,Nresp_add,Nresp_remv,updateBtn;
    private DefaultTableModel Header_dtm,Get_dtm,Post_dtm,contL_dtm,Nresp_dtm;
    private JTable Header_Tbl,Get_Tbl,Post_Tbl,contL_Tbl,Nresp_Tbl;
    private JScrollPane Header_scroll,Get_scroll,Post_scroll,contL_scroll,Nresp_scroll;
    private JScrollPane scrolltab;
    private JCheckBox compareStCode;
    private String[] row2={"",""};
    private boolean isChecked;
                
    int checkedResStatusCode,baseResStatusCode;
    
    IHttpRequestResponse checkRequestResponse;
    
    List<Integer> res_ConLength = new ArrayList<Integer>();
    List<Integer> Nres_ConLength = new ArrayList<Integer>();
    
    List<String> not_resData = new ArrayList<String>();
    
    List<String> true_resData = new ArrayList<String>();
    
    Map<String,String> req_Headers=new HashMap<String,String>();
    
    Map<String,String> req_Url=new HashMap<String,String>();
    
    Map<String,String> req_Body=new HashMap<String,String>();
        
    
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) 
	{
		// keep a reference to our callbacks object
        this.callbacks = callbacks;
        		
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name //Privilege Escalation Tests
		callbacks.setExtensionName("PrivsEscs");

		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);
		
		
		//get the output stream for info messages
		output = callbacks.getStdout();
		
		/* 
		 * Building UI tab for user inputs
		 */
		SwingUtilities.invokeLater(new Runnable()
		{

			@Override
			public void run() 
			{
				MainPane = new JPanel();
				JPanel HeaderPan=new JPanel();
				JPanel GetPan=new JPanel();
				JPanel PostPan=new JPanel();
				JPanel contLPan=new JPanel();
				JPanel NrespPan=new JPanel();
				JPanel updtPan=new JPanel();
				
				compareStCode=new JCheckBox("Test only when Response status codes are same");
				compareStCode.addItemListener(new ItemListener() {
					
					@Override
					public void itemStateChanged(ItemEvent e) {
						if (e.getStateChange() == ItemEvent.SELECTED)
						{
							isChecked=true;
							compareStCode.setSelected(true);	
						}
						else
						{
							isChecked=false;
							compareStCode.setSelected(false);	
						}
						
					}
				});
							
				updateBtn=new JButton("Update Parameters");
				
												
				Header_add=new JButton("Add");
				Header_remv=new JButton("Remove");
				Header_dtm=new DefaultTableModel();
				Header_Tbl=new JTable(Header_dtm);
				Header_dtm.addColumn("Header Name");
				Header_dtm.addColumn("Header Value");
				Header_scroll=new JScrollPane(Header_Tbl);
				Header_scroll.setPreferredSize(new Dimension(500,140));
							
				Get_add=new JButton("Add");
				Get_remv=new JButton("Remove");
				Get_dtm=new DefaultTableModel();
				Get_Tbl=new JTable(Get_dtm);
				Get_dtm.addColumn("GET ParamName");
				Get_dtm.addColumn("GET ParamValue");
				Get_scroll=new JScrollPane(Get_Tbl);
				Get_scroll.setPreferredSize(new Dimension(500,140));
							
				Post_add=new JButton("Add");
				Post_remv=new JButton("Remove");
				Post_dtm=new DefaultTableModel();
				Post_Tbl=new JTable(Post_dtm);
				Post_dtm.addColumn("Post ParamName");
				Post_dtm.addColumn("Post ParamValue");
				Post_scroll=new JScrollPane(Post_Tbl);
				Post_scroll.setPreferredSize(new Dimension(500,140));
								
				Nresp_add=new JButton("Add");
				Nresp_remv=new JButton("Remove");
				Nresp_dtm=new DefaultTableModel();
				Nresp_Tbl=new JTable(Nresp_dtm);
				Nresp_dtm.addColumn("Response contains below text");
				Nresp_dtm.addColumn("Escalated(Yes/No) say Y or N (default N)");
				Nresp_scroll=new JScrollPane(Nresp_Tbl);
				Nresp_scroll.setPreferredSize(new Dimension(500,140));
								
				contL_add=new JButton("Add");
				contL_remv=new JButton("Remove");
				contL_dtm=new DefaultTableModel();
				contL_Tbl=new JTable(contL_dtm);
				contL_dtm.addColumn("Response contains Content-Length");
				contL_dtm.addColumn("Escalated(Yes/No) say Y or N (default N)");
				
				contL_scroll=new JScrollPane(contL_Tbl);
				contL_scroll.setPreferredSize(new Dimension(500,140));
							
				AddRemoveTableActions addRemoveTable=new AddRemoveTableActions();
				
				Header_add.addActionListener(addRemoveTable);
				Header_remv.addActionListener(addRemoveTable);
				
				Get_add.addActionListener(addRemoveTable);
				Get_remv.addActionListener(addRemoveTable);
				
				Post_add.addActionListener(addRemoveTable);
				Post_remv.addActionListener(addRemoveTable);
				
				Nresp_add.addActionListener(addRemoveTable);
				Nresp_remv.addActionListener(addRemoveTable);
								
				contL_add.addActionListener(addRemoveTable);
				contL_remv.addActionListener(addRemoveTable);
												
				updateBtn.addActionListener(addRemoveTable);
				
				HeaderPan.add(Header_scroll);
				HeaderPan.add(Header_add);
				HeaderPan.add(Header_remv);
								
				GetPan.add(Get_scroll);
				GetPan.add(Get_add);
				GetPan.add(Get_remv);
				
				PostPan.add(Post_scroll);
				PostPan.add(Post_add);
				PostPan.add(Post_remv);
								
				NrespPan.add(Nresp_scroll);
				NrespPan.add(Nresp_add);
				NrespPan.add(Nresp_remv);
								
				contLPan.add(contL_scroll);
				contLPan.add(contL_add);
				contLPan.add(contL_remv);
				
				updtPan.add(compareStCode);
				updtPan.add(updateBtn);
				
				GridLayout fl=new GridLayout(4,2);
				
				MainPane.setLayout(fl);
				MainPane.add(HeaderPan);
				MainPane.add(GetPan);
				MainPane.add(PostPan);
				MainPane.add(NrespPan);
				MainPane.add(contLPan);
				MainPane.add(updtPan);
				
				scrolltab=new JScrollPane(MainPane);
							
				// customize our UI components
                callbacks.customizeUiComponent(scrolltab);
				
				
				// add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
				
			}
			
			//UI operations
		 	class AddRemoveTableActions implements ActionListener
		 	{

		 		@Override
		 		public void actionPerformed(ActionEvent event) 
		 		{
		 			if(Header_add.equals(event.getSource()))
		 			{
		 				addHeaderRow();
		 			}
		 			else if(Header_remv.equals(event.getSource()))
		 			{
		 				remvHeaderRow();
		 			}
		 			else if(Get_add.equals(event.getSource()))
		 			{
		 				addGetRow();
		 			}
		 			else if(Get_remv.equals(event.getSource()))
		 			{
		 				remvGetRow();
		 			}
		 			else if(Post_add.equals(event.getSource()))
		 			{
		 				addPostRow();
		 			}
		 			else if(Post_remv.equals(event.getSource()))
		 			{
		 				remvPostRow();
		 			}
		 			else if(contL_add.equals(event.getSource()))
		 			{
		 				addcontLRow();
		 			}
		 			else if(contL_remv.equals(event.getSource()))
		 			{
		 				remvcontLRow();
		 			}
		 			else if(Nresp_add.equals(event.getSource()))
		 			{
		 				addNrespRow();
		 			}
		 			else if(Nresp_remv.equals(event.getSource()))
		 			{
		 				remvNrespRow();
		 			}
		 			else if(updateBtn.equals(event.getSource()))
		 			{
		 				updateParams();
		 			}
				
		 		}
		 		
		 		private void updateParams()
		 		{
		 			
		 			req_Headers.clear();
		 			req_Url.clear();
		 			req_Body.clear();
		 			not_resData.clear();
		 			true_resData.clear();
		 			res_ConLength.clear();
		 			Nres_ConLength.clear();
		 					 			
		 			for(int i=0;i<Header_dtm.getRowCount();i++)
		 			{
		 				println("Updated Header ["+Header_dtm.getValueAt(i, 0).toString()+":"+Header_dtm.getValueAt(i, 1).toString()+"]");
		 				req_Headers.put(Header_dtm.getValueAt(i, 0).toString(), Header_dtm.getValueAt(i, 1).toString());
		 				
		 			}
		 			for(int i=0;i<Get_dtm.getRowCount();i++)
		 			{
		 				println("Updated GET ["+Get_dtm.getValueAt(i, 0).toString()+"="+Get_dtm.getValueAt(i, 1).toString()+"]");
		 				req_Url.put(Get_dtm.getValueAt(i, 0).toString(), Get_dtm.getValueAt(i, 1).toString());
		 				
		 			}
		 			for(int i=0;i<Post_dtm.getRowCount();i++)
		 			{
		 				println("Updated POST ["+Post_dtm.getValueAt(i, 0).toString()+"="+Post_dtm.getValueAt(i, 1).toString()+"]");
		 				req_Body.put(Post_dtm.getValueAt(i, 0).toString(), Post_dtm.getValueAt(i, 1).toString());
		 				
		 			}
		 			for(int i=0;i<Nresp_dtm.getRowCount();i++)
		 			{
		 				if(Nresp_dtm.getValueAt(i, 1).toString().equalsIgnoreCase("Y"))
		 				{
		 					println("If Response Contains ["+Nresp_dtm.getValueAt(i, 0).toString()+"] then it is Privilege Escalated.");
		 					true_resData.add(Nresp_dtm.getValueAt(i, 0).toString());
		 				}
		 				else
		 				{
		 					println("If Response Contains ["+Nresp_dtm.getValueAt(i, 0).toString()+"] then it is not Privilege Escalated.");
		 					not_resData.add(Nresp_dtm.getValueAt(i, 0).toString());
		 				}
		 						 				
		 			}
		 			for(int i=0;i<contL_dtm.getRowCount();i++)
		 			{
		 				if(contL_dtm.getValueAt(i, 1).toString().equalsIgnoreCase("Y"))
		 				{
		 					println("If Response content Length is: ["+Integer.parseInt(contL_dtm.getValueAt(i, 0).toString())+"] then it is privilege Escalated.");
		 					res_ConLength.add(Integer.parseInt(contL_dtm.getValueAt(i, 0).toString()));
		 				}
		 				else
		 				{
		 					println("If Response content Length is: ["+Integer.parseInt(contL_dtm.getValueAt(i, 0).toString())+"] then it is not privilege Escalated.");
		 					Nres_ConLength.add(Integer.parseInt(contL_dtm.getValueAt(i, 0).toString()));
		 				}
		 				
		 			}
		 			println("UPDATED--------------------------------------");
		 			
		 		}
		 		private void addHeaderRow()
				{
					Header_dtm.addRow(row2);
				}
				private void remvHeaderRow()
				{
					int selrow=Header_Tbl.getSelectedRow();
					if(selrow>=0)
						Header_dtm.removeRow(selrow);
				}
				private void addGetRow()
				{
					Get_dtm.addRow(row2);
				}
				private void remvGetRow()
				{
					int selrow=Get_Tbl.getSelectedRow();
					if(selrow>=0)
						Get_dtm.removeRow(selrow);
				}
				private void addPostRow()
				{
					Post_dtm.addRow(row2);
				}
				private void remvPostRow()
				{
					int selrow=Post_Tbl.getSelectedRow();
					if(selrow>=0)
						Post_dtm.removeRow(selrow);
				}
				private void addcontLRow()
				{
					
					contL_dtm.addRow(row2);
				}
				private void remvcontLRow()
				{
					int selrow=contL_Tbl.getSelectedRow();
					if(selrow>=0)
						contL_dtm.removeRow(selrow);
				}
				private void addNrespRow()
				{
					Nresp_dtm.addRow(row2);
				}
				private void remvNrespRow()
				{
					int selrow=Nresp_Tbl.getSelectedRow();
					if(selrow>=0)
						Nresp_dtm.removeRow(selrow);
				}			 
		 	}
		});
		println("Successfully Loaded Privilege Escalation Extender");
	}//end of UI logic
	
	@Override
	public String getTabCaption() {
		
		return "PrivilegeEsclation";
	}


	@Override
	public Component getUiComponent() {
		
		return scrolltab;
	}
	
	/*
	 * Method called by passive
	 */
	public List<int[]> getMatches(IHttpRequestResponse CheckedReqRes, byte[] match,int baseResStatusCode)
	{
		
		IResponseInfo resInfo=helpers.analyzeResponse(CheckedReqRes.getResponse());
				
		//Getting Response Status Code
		checkedResStatusCode=resInfo.getStatusCode();
		
		//****************************************************************//
		//logic for comparing the responses based on conditions
		/*
		 * When non-privileged user response status code mismatch with base response or privileged user response status code
		 * then the request is not privilege escalated.
		 */
		
		//when CheckBox checked compare the status codes then performTest() otherwise do performTest()
		if(isChecked)
		{
			if(baseResStatusCode==checkedResStatusCode)
			{
				return performTest(CheckedReqRes, match, baseResStatusCode);
			}
			else
			{
				return null;
			}
		}
		else
		{
			return performTest(CheckedReqRes, match, baseResStatusCode);
		}
		
	}
	
	public List<int[]> performTest(IHttpRequestResponse CheckedReqRes, byte[] match,int baseResStatusCode)
	{
		List<int[]> matches=new ArrayList<int[]>();	
		int start=0;
		int mp=0;
		
		IResponseInfo resInfo=helpers.analyzeResponse(CheckedReqRes.getResponse());
		List<String> resHeaders=resInfo.getHeaders();
		
		String newResp=new String(CheckedReqRes.getResponse());
		int conLength=0;
		
		//Getting Response Content-Length
		for(int rh=0;rh<resHeaders.size();rh++)
		{
			if(resHeaders.get(rh).startsWith("Content-Length:"))
			{
				String con[]=resHeaders.get(rh).split(":");
				String ss[]=con[1].split(" ");
				String s=ss[1];
				conLength=new Integer(s).intValue();
				break;
			}
		}
		
		//Getting Response Status Code
		//checkedResStatusCode=resInfo.getStatusCode();
		
		//Test privilege escalation based on false condition
		//if the response contains the below text then it is not privilege escalated
		/*
		 * When a non-privileged user sends the privileged request then application throws some Error messages
		 * for example 'You do not have permission to access the resource' or 'Access Denied' etc. 
		 * based on the message/text tool will decide whether the request is privilege escalated or not.
		 */
		for(int k=0;k<not_resData.size();k++)
		{
			
			if(newResp.contains(not_resData.get(k)))
			{	
				match=not_resData.get(k).getBytes();
			    start = helpers.indexOf(CheckedReqRes.getResponse(), match, true, start, CheckedReqRes.getResponse().length);
			    
			    if (start == -1)
			      {
			         break;
			      }
			    
				return null;
			 }
			else
			{
				mp=1;
			}
		 }
		
		//Test privilege escalation based on true condition
		//if the response contains the below text then it is privilege escalated
		
		for(int td=0;td<true_resData.size();td++)
		{
			match=true_resData.get(td).getBytes();
			if(newResp.contains(new String(match)))
			{
				
				while (start < CheckedReqRes.getResponse().length)
		        {
		            start = helpers.indexOf(CheckedReqRes.getResponse(), match, true, start, CheckedReqRes.getResponse().length);
		            if (start == -1)
		            {
		                break;
		            }
		            else
		            {
		            	matches.add(new int[] { start, start + match.length });
		            	start += match.length;
		            	
		            }
		          }
				 return matches;
			 }
		}
		
		//True Condition - Escalated
		for(int rc=0;rc<res_ConLength.size();rc++)
		{
			if(conLength==Integer.parseInt(res_ConLength.get(rc).toString()))
			{
				match=res_ConLength.get(rc).toString().getBytes();
				while (start < CheckedReqRes.getResponse().length)
		        {
		            start = helpers.indexOf(CheckedReqRes.getResponse(), match, true, start, CheckedReqRes.getResponse().length);
		            if (start == -1)
		            {
		                break;
		            }
		            else
		            {
		            	matches.add(new int[] { start, start + match.length });
		            	start += match.length;
		            	
		            }
		         }
				 return matches;
			 }
		}
		
		//Test privilege escalation based on content length
		//if the response content-Length matches then it is not privilege escalated
		/*
		 * When application is Forbidden the request or Redirect to error/login pages 
		 * then those responses will contains the fixed length
		 */
		for(int rc=0;rc<Nres_ConLength.size();rc++)
		{
			if(conLength==Integer.parseInt(Nres_ConLength.get(rc).toString()))
			{
				match=Nres_ConLength.get(rc).toString().getBytes();
				start = helpers.indexOf(CheckedReqRes.getResponse(), match, true, start, CheckedReqRes.getResponse().length);
				if (start == -1)
		           {
		               break;
		           }
				return null;
			 }
			else
			{
				mp=1;
			}
												
		 }
		
		/*
		 * this should be here
		 * When No Condition is satisfied this might be Privilege Escalated or False Positive
		 * 
		 */
		
		if(mp!=0)
		{
			return matches;
		}
	 return null;
	 
	} //end of logic		
	
	//update GET parameter values only if parameters exist
	public boolean isGetParameterExist(IRequestInfo rinfo,String key)
	{
		boolean exist=false;
		IParameter parameter;
		List<IParameter> parameters=rinfo.getParameters();
		Iterator<IParameter> iterator=parameters.iterator();
		while(iterator.hasNext())
		{
			parameter=iterator.next();
			if(parameter.getType()==IParameter.PARAM_URL&&parameter.getName().equalsIgnoreCase(key))
			{
				exist=true;
				break;
			}
		}
		
		return exist;
	}
	
	//update POST parameter values only if parameters exist
	/*
	 * What if the request POST data is JSON or XML 
	 * this is an improvement area I need to concentrate
	 */
	public boolean isPostParameterExist(IRequestInfo rinfo,String key)
	{
		boolean exist=false;
		IParameter parameter;
		List<IParameter> parameters=rinfo.getParameters();
		Iterator<IParameter> iterator=parameters.iterator();
		while(iterator.hasNext())
		{
			parameter=iterator.next();
			if(parameter.getType()==IParameter.PARAM_BODY&&parameter.getName().equalsIgnoreCase(key))
			{
				exist=true;
				break;
			}
		}
		
		return exist;
	}
	
	//Not calling this method ---
	public boolean isPostJSONParameterExist(IRequestInfo rinfo,String key)
	{
		boolean exist=false;
		IParameter parameter;
		List<IParameter> parameters=rinfo.getParameters();
		Iterator<IParameter> iterator=parameters.iterator();
		while(iterator.hasNext())
		{
			parameter=iterator.next();
			if(parameter.getType()==IParameter.PARAM_JSON&&parameter.getName().equalsIgnoreCase(key))
			{
				exist=true;
				break;
			}
		}
		
		return exist;
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) 
	{
		IHttpService httpService=baseRequestResponse.getHttpService();
		IRequestInfo rinfo=helpers.analyzeRequest(baseRequestResponse);
		List<String> headers=rinfo.getHeaders();		
		IResponseInfo respInfo=helpers.analyzeResponse(baseRequestResponse.getResponse());
		baseResStatusCode=respInfo.getStatusCode();
		request=new String(baseRequestResponse.getRequest());
		String reqBody=request.substring(rinfo.getBodyOffset());
		//update HEADERS in the Request
		//new headers will be added and existing headers will be updated
		Set<String> reqHeadKeys=req_Headers.keySet();
		for(int i=0;i< headers.size();i++)
	   	{
			for(String key:reqHeadKeys)
			{
				if(headers.get(i).startsWith(key))
				{
					headers.remove(i);
				}
			}
		}
		for(String key:reqHeadKeys)
		{
			headers.add(key+": "+req_Headers.get(key));
		}
		
		
		//Request with updated Headers
		byte[] completeReq=helpers.buildHttpMessage(headers, reqBody.getBytes());		
		//update POST body parameters in the Request
		Set<String> reqPostKeys=req_Body.keySet();
		for(String key:reqPostKeys)
		{
			if(isPostParameterExist(rinfo,key))
			{
				completeReq=helpers.updateParameter(completeReq, helpers.buildParameter(key, req_Body.get(key), IParameter.PARAM_BODY));
			}
		}
		//update GET query parameters in the Request
		Set<String> reqUrlKeys=req_Url.keySet();
		for(String key:reqUrlKeys)
		{
			if(isGetParameterExist(rinfo,key))
				completeReq=helpers.updateParameter(completeReq, helpers.buildParameter(key, req_Url.get(key), IParameter.PARAM_URL));
		}
		IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), callbacks.makeHttpRequest(httpService, completeReq).getRequest());	
		List<int[]> matches = getMatches(checkRequestResponse,null,baseResStatusCode);
		if(matches!=null)
		{
			//report the issue
			List<IScanIssue>issues = new ArrayList<>(1);
		    issues.add(new CustomScanIssue(
		    checkRequestResponse.getHttpService(),
		    helpers.analyzeRequest(checkRequestResponse).getUrl(), 
		    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, null, matches) }, 
		    "Priviege Escalation",
		    "Privileged User Page is accessible by non-privileged User",
		    "High"));
		    return issues;
		}
		else
		{
			return null;
		}				
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) 
	{
		return null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		if(existingIssue.getHttpMessages().equals(newIssue.getHttpMessages()))
			return -1;
		else
			return 0;
	}
	
	private void println(String toPrint) 
	{
		try
		{
		    output.write(toPrint.getBytes());
		    output.write("\n".getBytes());
		    output.flush();
		} 
		catch (IOException ioe) 
		{
		    ioe.printStackTrace();
		} 
	 }
	
}

//class implementing IScanIssue to hold our custom scan issue details
class CustomScanIssue implements IScanIssue
{
	 private IHttpService httpService;
	 private URL url;
	 private IHttpRequestResponse[] httpMessages;
	 private String name;
	 private String detail;
	 private String severity;
	
	 public CustomScanIssue(IHttpService httpService,URL url,IHttpRequestResponse[] httpMessages,String name,String detail,String severity)
	 {
	     this.httpService = httpService;
	     this.url = url;
	     this.httpMessages = httpMessages;
	     this.name = name;
	     this.detail = detail;
	     this.severity = severity;
	 }
	 
	 @Override
	 public URL getUrl()
	 {
	     return url;
	 }
	
	 @Override
	 public String getIssueName()
	 {
	     return name;
	 }
	
	 @Override
	 public int getIssueType()
	 {
	     return 0;
	 }
	
	 @Override
	 public String getSeverity()
	 {
	     return severity;
	 }
	
	 @Override
	 public String getConfidence()
	 {
	     return "Certain";
	 }
	
	 @Override
	 public String getIssueBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getRemediationBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getIssueDetail()
	 {
	     return detail;
	 }
	
	 @Override
	 public String getRemediationDetail()
	 {
	     return null;
	 }
	
	 @Override
	 public IHttpRequestResponse[] getHttpMessages()
	 {
	     return httpMessages;
	 }
	
	 @Override
	 public IHttpService getHttpService()
	 {
	     return httpService;
	 }
  
}
