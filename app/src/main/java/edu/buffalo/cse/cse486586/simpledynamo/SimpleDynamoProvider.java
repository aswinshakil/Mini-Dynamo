package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;


import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;


import static java.net.InetAddress.getByAddress;

public class SimpleDynamoProvider extends ContentProvider {

	static final int SERVER_PORT = 10000;
	static String[] emulatorPorts = {"5554", "5556","5558", "5560", "5562" };
	static final String KEY="key";
	static final String VALUE="value";
	static String myPort;
	static String portStr;
	static String hashedPort;
	static String suc;
	static String pre;
	static String pre2;
	final String  DELIM= "&&";
	final String  DELIM2 = "@@";
	TreeMap<String, ArrayList<String> > sucPort = new TreeMap<String, ArrayList<String>>();
	HashMap<String, String> pred = new HashMap<String, String>();
	boolean recovered = false;
	ArrayList<String> temp1 = new ArrayList<String>();
	ArrayList<String> temp2 = new ArrayList<String>();
	ArrayList<String> temp3 = new ArrayList<String>();
	ArrayList<String> temp4 = new ArrayList<String>();
	ArrayList<String> temp5 = new ArrayList<String>();
	ArrayList<String> mydataports = new ArrayList<String>();
	Uri providerUri = new Uri.Builder().scheme("content").authority("edu.buffalo.cse.cse486586.simpledynamo.provider").build();
	ArrayList<String> recoveryPorts = new ArrayList<String>();


	@Override
	public synchronized int delete(Uri uri, String selection, String[] selectionArgs) {
		while(!recovered){
			try {
			Thread.sleep(400);
		} catch (InterruptedException e) {
			e.printStackTrace();
			}
		}

		String[] selectionSplit = selection.split(DELIM);
		if(selectionSplit.length>1){
			deleteLocal(selectionSplit[1]);
		}else {
			try {
				String keyHash = genHash(selection);
				ArrayList<String> portList = correctPort(keyHash);
				if (selection.equals("*")) {
					ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
					for (String file : files) {
						getContext().deleteFile(file);
					}
					for(String emulator: emulatorPorts){
						if(emulator.equals(portStr)){
							continue;
						}
						Socket socket1 = new Socket(getByAddress(new byte[]{10, 0, 2, 2}),
								(Integer.parseInt(emulator) * 2));
						String msg = "DELETEALL" + DELIM + "@";
						DataOutputStream out = new DataOutputStream(socket1.getOutputStream());
						out.writeUTF(msg);
						out.flush();
					}
				} else if (selection.equals("@")) {
					ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
					for (String file : files) {
						getContext().deleteFile(file);
					}
				} else {
					ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
					if (portList.contains(portStr)) {  //  && files.contains(selection)
						deleteLocal(selection);
						for (String port : portList) {
							if (port.equals(portStr)) {
								continue;
							}
							Socket socket1 = new Socket(getByAddress(new byte[]{10, 0, 2, 2}),
									(Integer.parseInt(port) * 2));
							String msg = "DELETE" + DELIM + selection;
							DataOutputStream out = new DataOutputStream(socket1.getOutputStream());
							out.writeUTF(msg);
							out.flush();
						}
					} else {
						for (String port : portList) {
							Socket socket1 = new Socket(getByAddress(new byte[]{10, 0, 2, 2}),
									(Integer.parseInt(port) * 2));
							String msg = "DELETE" + DELIM + selection;
							DataOutputStream out = new DataOutputStream(socket1.getOutputStream());
							out.writeUTF(msg);
							out.flush();
						}
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}

		return 0;
	}

	public void deleteLocal(String key){
		getContext().deleteFile(key);
	}

	@Override
	public String getType(Uri uri) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Uri insert(Uri uri, ContentValues values) {
		while(!recovered){
			try {
				Thread.sleep(400);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		String key = values.getAsString("key");
		String value = values.getAsString("value");
			try {
				String keyHash = genHash(key);
				ArrayList<String> portList = correctPort(keyHash);
				for (String port : portList) {
					Socket socket1 = new Socket(getByAddress(new byte[]{10, 0, 2, 2}),
							(Integer.parseInt(port) * 2));
					String msg = "INSERT" + DELIM + key + DELIM + value + DELIM2 + portList.get(0);
					DataOutputStream out = new DataOutputStream(socket1.getOutputStream());
					out.writeUTF(msg);
					out.flush();
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		return null;
	}
	public synchronized void insertLocal(String key,String value){
			try {
				FileOutputStream fileOutput = getContext().openFileOutput(key, getContext().MODE_PRIVATE);
				fileOutput.write(value.getBytes());
				fileOutput.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	public ArrayList<String> correctPort(String hashkey){
		if(sucPort.ceilingKey(hashkey)==null || sucPort.floorKey(hashkey)==null)
		{
			return sucPort.get(sucPort.firstKey());

		}
		else{
			return sucPort.get(sucPort.ceilingKey(hashkey));
		}
	}

	@Override
	public boolean onCreate() {

		TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
		portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
		myPort = String.valueOf((Integer.parseInt(portStr) * 2));

		try {
			hashedPort = genHash(portStr);
			temp1.add("5554");
			temp1.add("5558");
			temp1.add("5560");
			sucPort.put(genHash("5554"), temp1);


			temp2.add("5558");
			temp2.add("5560");
			temp2.add("5562");
			sucPort.put(genHash("5558"), temp2);

			temp3.add("5560");
			temp3.add("5562");
			temp3.add("5556");
			sucPort.put(genHash("5560"), temp3);


			temp4.add("5562");
			temp4.add("5556");
			temp4.add("5554");
			sucPort.put(genHash("5562"), temp4);

			temp5.add("5556");
			temp5.add("5554");
			temp5.add("5558");
			sucPort.put(genHash("5556"), temp5);

			pred.put("5554","5556");
			pred.put("5558","5554");
			pred.put("5560","5558");
			pred.put("5562","5560");
			pred.put("5556","5562");

			ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
			new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		suc = sucPort.get(hashedPort).get(1);
		pre = pred.get(portStr);
		pre2 =pred.get(pre);
		recoveryPorts.add(suc);
		recoveryPorts.add(pre);
		recoveryPorts.add(pre2);

		mydataports.add(portStr);
		mydataports.add(pre);
		mydataports.add(pre2);

		File file_path = new File(getContext().getFilesDir().getAbsolutePath());
		if(file_path.listFiles().length>0){
			recovered = false;
			new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "RECOVERY");
		}else{
			recovered=true;
		}
		return false;
	}

	@Override
	public Cursor query(Uri uri, String[] projection, String selection,
						String[] selectionArgs, String sortOrder) {
		while(!recovered){
			try {
				Thread.sleep(400);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		String[] columnNames = {"key", "value"};
		MatrixCursor matrixCursor = new MatrixCursor(columnNames);
		if (selection.equals("@")) {
			try {
				ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
				for (String file : files) {
					FileInputStream fileInput = getContext().openFileInput(file);
					InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
					BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
					String output = bufferedReader.readLine();
					String[] outputSplit = output.split(DELIM2);
					matrixCursor.addRow(new Object[]{file,outputSplit[0]});
				}
				return matrixCursor;

			} catch (IOException e) {
				e.printStackTrace();
			}
		}else if (selection.equals("*")) {
			try {
				ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));

				for (String emulator : emulatorPorts) {
					Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
							(Integer.parseInt(emulator) * 2));
					String msg = "QUERYALL";
					DataOutputStream out = new DataOutputStream(socket2.getOutputStream());
					out.writeUTF(msg);
					out.flush();
					String input ="";
					try {
						DataInputStream in = new DataInputStream(new BufferedInputStream(socket2.getInputStream()));
						input = in.readUTF();
					} catch (IOException e) {
						Log.e("Query","Catch read input");
					}
					if(!input.equals("")){
						String[] inputSplit = input.split(DELIM);
						for (int i = 1; i < inputSplit.length - 1; i=i+2) {
							String k = inputSplit[i];
							String[] v = inputSplit[i + 1].split(DELIM2);
							String[] row = {k, v[0]};
							matrixCursor.addRow(new Object[]{k, v[0]});
						}
					}

				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			return matrixCursor;
		}else {
			HashMap<String,Integer> count = new HashMap<String, Integer>();
			try {
				String keyhash = genHash(selection);
				ArrayList<String> ports = correctPort(keyhash);
				for(String port: ports){
					Socket socket7 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
							(Integer.parseInt(port) * 2));
					String msg = "QUERY"+DELIM+selection;
					DataOutputStream out = new DataOutputStream(socket7.getOutputStream());
					out.writeUTF(msg);
					out.flush();
					DataInputStream in = new DataInputStream(new BufferedInputStream(socket7.getInputStream()));
					String inp = "";
					try {
						inp = in.readUTF();
					} catch (Exception e) {
						Log.e("Single Query","Catch read input");
					}
					if(!inp.equals("")) {
						String[] inpsplit = inp.split(DELIM2);
						String input = inpsplit[0];
						if (count.containsKey(input))
						{
							count.put(input, count.get(input)+1);
						}
						else
						{
							count.put(input, 1);
						}

					}
				}
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (UnknownHostException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			String element = "";
			int frequency = 0;
			Set<Map.Entry<String, Integer>> entrySet = count.entrySet();

			for (Map.Entry<String, Integer> entry : entrySet)
			{
				if(entry.getValue() > frequency)
				{
					element = entry.getKey();
					frequency = entry.getValue();
				}
			}
			matrixCursor.addRow(new Object[]{selection, element});
			return matrixCursor;

		}

		return null;
	}

	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {

		return 0;
	}

	private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

		@Override
		protected synchronized Void doInBackground(ServerSocket... sockets) {
			ServerSocket serverSocket = sockets[0];
			try {
				while (true) {
					Socket socket = serverSocket.accept();
					DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
					String message = input.readUTF();
					String[] split = message.split(DELIM);
					if (split[0].equals("INSERT")) {
						insertLocal(split[1],split[2]);
					} else if (split[0].equals("DELETE")) {
						Uri newUri = providerUri;
						delete(newUri, "dummy" + DELIM + split[1], null);

					} else if (split[0].equals("DELETEALL")) {
						Uri newUri = providerUri;
						delete(newUri, split[1], null);

					}else if (split[0].equals("QUERYALL")) {
						String toSend = "";
						String[] files = getContext().fileList();

						for (String file : files) {
							FileInputStream fileInput = getContext().openFileInput(file);
							InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
							BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
							String output = bufferedReader.readLine();
							toSend = toSend + DELIM + file + DELIM + output;

						}
						DataOutputStream out = new DataOutputStream(socket.getOutputStream());
						out.writeUTF(toSend);
						out.flush();
					} else if (split[0].equals("QUERY")) {
							ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
							FileInputStream fileInput = getContext().openFileInput(split[1]);
							InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
							BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
							String output = bufferedReader.readLine();
							try {
								DataOutputStream out = new DataOutputStream(socket.getOutputStream());
								out.writeUTF(output);
								out.flush();
							} catch (IOException e) {
								e.printStackTrace();
							}
					}else if (split[0].equals("RECOVERY")) {
						ArrayList<String> files = new ArrayList<String>(Arrays.asList(getContext().fileList()));
						String send ="dummy";
						for(String file: files){
							FileInputStream fileInput = getContext().openFileInput(file);
							InputStreamReader inputStreamReader = new InputStreamReader(fileInput);
							BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
							String output = bufferedReader.readLine();
							send = send + DELIM + file + DELIM + output;
						}
						try {
							DataOutputStream out = new DataOutputStream(socket.getOutputStream());
							out.writeUTF(send);
							out.flush();
						} catch (IOException e) {
							e.printStackTrace();
						}

					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			return null;
		}
	}

	public synchronized void insertrecovery(String key,String value){
		try {
			FileOutputStream fileOutput = getContext().openFileOutput(key, getContext().MODE_PRIVATE);
			fileOutput.write(value.getBytes());
			fileOutput.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private class ClientTask extends AsyncTask<String, Void, Void> {

		@Override
		protected Void doInBackground(String... msgs) {

			String[] split = msgs[0].split(DELIM);
			if(split[0].equals("RECOVERY")){
				try {
					for(String recovery: emulatorPorts) {
						if(recovery.equals(portStr)){
							continue;
						}
						Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
								(Integer.parseInt(recovery) * 2));
						String portRequested = "";
						String msg = "RECOVERY" + DELIM + portRequested;
						DataOutputStream out = new DataOutputStream(socket.getOutputStream());
						out.writeUTF(msg);
						out.flush();
						DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
						String allmsg = "";

						try {
							allmsg = input.readUTF();
						} catch (Exception e) {
							e.printStackTrace();
						}
						if (!allmsg.equals("")) {
							String[] msgSplit = allmsg.split(DELIM);
							for (int i = 1; i < msgSplit.length - 1; i = i + 2) {
								String k = msgSplit[i];
								String[] v = msgSplit[i + 1].split(DELIM2);
								if(mydataports.contains(v[1])) {
									insertrecovery(k, msgSplit[i+1]);
								}
							}
						}
					}
					recovered=true;
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
    	return null;

		}
	}

	private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}
