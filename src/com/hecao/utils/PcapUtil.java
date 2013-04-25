package com.hecao.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Set;
import java.util.zip.GZIPInputStream;

public class PcapUtil {
	
	//java -Xmx1024m com.hecao.test.PcapUtil
	
	public static final int PCAP_MAGIC_NUM = 0xA1B2C3D4;
	
	public static final String[] DEST_WHITE_LIST = new String[]{"meimei", "renren"};
	
	public static HashMap<String, byte[]> sDataMap = new HashMap<String, byte[]>();
	private static String sCurrentKey = null;
	
	public static HashMap<String, byte[]> getData() {
		
		initDataMap();
		
//		Set<String> keySet = sDataMap.keySet();
//		for (String key : keySet) {
//			System.out.println("key :" + key);
//			byte[] data = sDataMap.get(key);
//			System.out.println("data : " + (data == null ? "null" : new String(data)));
//		}
		
		return sDataMap;
	}
	
	private static void initDataMap() {
		System.out.println("=========");

		File file = new File("/Users/caohe/Downloads/final.pcap");
		try {
			sCurrentKey = null;
			checkPcap(file);
			
			ArrayList<TcpPack> packs = processPcapPackage(sIn);
			HashMap<String, HttpConn> dict = new HashMap<String, HttpConn>();
			for (TcpPack pack : packs) {
//				System.out.println(pack.source + ":" + pack.sourcePort + " --> " + pack.dest + ":" + pack.destPort);
				String key = pack.genKey();
//				System.out.println(key + " " + pack.pacType);
				if (dict.containsKey(key)) {
					dict.get(key).append(pack);
					if (pack.pacType == -1) {
						dict.get(key).output();
						dict.remove(key);
					}
				} else if (pack.pacType == 1) {
					dict.put(key, new HttpConn(pack));
				}
				
			}
			
			Set<String> keySet = dict.keySet();
			for (String key : keySet) {
				dict.get(key).output();
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("======init complete=====");
	
	}

	public static void main(String[] args) {		
		getData();
		
	}
	
	static class CheckResult {
		
		boolean valid;
		boolean bigEndian;
		
	}
	
	public static InputStream sIn;
	
	static class TcpPack {
		
		public TcpPack(String source, int sourcePort, String dest, int destPort, int pacType, long seq, long ack, byte[] body) {
			
			this.source = source;
			this.sourcePort = sourcePort;
			this.dest = dest;
			this.destPort = destPort;
			this.pacType = pacType;
			this.seq = seq;
			this.ack = ack;
			this.body = body;
//			this.direction = direction;
		}
		
		public String source;
		public int sourcePort;
		public String dest;
		public int destPort;
		public int pacType;
		public long seq;
		public long ack;
		public byte[] body;
		public int direction;
		
		public String genKey() {
			String skey = source + ":" + sourcePort;
			String dkey = dest + ":" + destPort;
			String key = "";
			if (skey.compareTo(dkey) < 0) {
				key = skey + "-" + dkey;
			} else {
				key = dkey + "-" + skey;
			}
			
			return key;
		}
		
	}
	
	public static boolean isHttpResponse(byte[] data) {
		
		String stringContent = new String(data);
		if (stringContent != null) {
			int index = stringContent.indexOf(' ');
			if (index < 0 || index > 10) {
				return false;
			}
			String start = stringContent.substring(0, index);
			return start.toUpperCase().startsWith("HTTP/");
		}
		return false;
	}
	
	public static boolean isHttpRequest(byte[] data) {
		
		
		String stringContent = new String(data);
//		System.out.println(" " + stringContent);
		if (stringContent != null) {
			int index = stringContent.indexOf(' ');
			if (index < 0 || index > 10) {
				return false;
			}
			String method = stringContent.substring(0, index);
//			System.out.println("===" + method);
			String[] valid = new String[]{"GET", "POST", "PUT", "DELETE"};
			for (String v : valid) {
				if (method.equalsIgnoreCase(v)) {
					return true;
				}
			}
		}
		
		return false;
	}
	
	private static String getHeaderValue(String line, String key) {
		String lcline = line.toLowerCase();
		int index = lcline.indexOf(key);
		if (index >= 0) {
			return lcline.substring(index + key.length()).trim();
		}
		return null;
	}
	
	private static byte[] readData(byte[] datas) {

		
		for (int i = 0 ; i < datas.length ; i ++) {
			
			if ((char) datas[i] == '\n') {
				if (i > 3) {
					if (((char)datas[i - 1]) == '\r' && ((char)(datas[i - 2])) == '\n' && ((char)(datas[i - 3]) == '\r') ) {
						byte[] temp = new byte[datas.length - i - 1];
						System.arraycopy(datas, i + 1, temp, 0, temp.length);
						datas = temp;
						break;
					}
				}
			}
		}

		ByteArrayInputStream gzipInputStream = new ByteArrayInputStream(datas);
		String string = unGzipBytesToString(gzipInputStream);
		if (isValidString(string)) {
//			System.out.println("==request==" + string);
			return string.getBytes();
		}
		return datas;
	}
	
	public static boolean isValidString(String s) {
		
		int min = 10;
		if (s == null || s.length() <= min){
			return false;
		}
		for (int i = 0 ; i < min ; i ++) {
			int chr = s.charAt(i);
			if (chr <= 0 || chr >= 177 || chr == '?') {
				return false;
			}
			
		}
		return true;
//		return s != null && !s.contains("?????");
		
	}
	
	private static byte[] readChunkedData(byte[] datas) {

//		System.out.println("==read data1==" + new String(datas) + "end");
		for (int i = 0 ; i < datas.length ; i ++) {
			
			if ((char) datas[i] == '\n') {
				if (i > 3) {
					if (((char)datas[i - 1]) == '\r' && ((char)(datas[i - 2])) == '\n' && ((char)(datas[i - 3]) == '\r') ) {
						byte[] temp = new byte[datas.length - i + 1];
						System.arraycopy(datas, i - 1, temp, 0, temp.length);
						datas = temp;
						break;
					}
				}
			}
		}
		
//		System.out.println("==read data==" + new String(datas) + "end");
		
		int start = 0;
		int state = 0;
		byte[] result = null;
		for (int i = 0 ; i < datas.length ; i ++) {
			if ((char)datas[i] == '\n') {
				if ((char) datas[i - 1] == '\r') {
					if (state == 0) {
						start = i;
						state = 1;
					} else if (state == 1) {
						String hexString = "";
						for (int j = start ; j <= i - 2 ; j ++) {
							hexString += (char) datas[j];
						}
//						System.out.println("wtf" + new String(datas));
						int length = Integer.parseInt(hexString.trim(), 16);
						byte[] temp = new byte[length + (result == null ? 0 : result.length)];
						if (result != null) {
							System.arraycopy(result, 0, temp, 0, result.length);
						}
						System.arraycopy(datas, i + 1, temp, (result == null ? 0 : result.length), length);
						result = temp;
						if (length == 0) {
							return result;
						}
						state = 0;
					}
				}
			}
//			System.out.println("====" + ((char)datas[i]));
		}
		
		return null;
	}
	
	public static boolean readRequest(ArrayList<TcpPack> packs) {

		if (packs.size() == 0) {
			return false;
		}
		
		Collections.sort(packs, new Comparator<TcpPack>() {

			@Override
			public int compare(TcpPack o1, TcpPack o2) {
				return (int) (o1.seq - o2.seq);
			}
		});
		
		byte[] body = null;
		if (packs.size() > 0) {
			body = packs.get(0).body;
		}
		
		if (packs.size() > 1) {
			for (int i = 1 ; i < packs.size() ; i++ ){
				byte[] temp = new byte[body.length + packs.get(i).body.length];
				System.arraycopy(body, 0, temp, 0, body.length);
				System.arraycopy(packs.get(i).body, 0, temp, body.length, packs.get(i).body.length);
				body = temp;
//				System.out.println("||||" + new String(body));
			}
		}
		
		int pos = 0;
		int contentLen = 0;
		String transferEncoding = "";
		String contentEncoding = "";
		String contentType = "";
		boolean gzip = false;
		boolean isChunked = false;
		String host = "";
		String request = "";

		ByteArrayInputStream bis = new ByteArrayInputStream(body);
		InputStreamReader isr = new InputStreamReader(bis);
		BufferedReader reader = new BufferedReader(isr);
		while (true) {

			try {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
//				System.out.println("line" + line);
				
				if (line.toLowerCase().startsWith("content-length:")) {
					contentLen = Integer.valueOf(getHeaderValue(line, "content-length:"));
//					System.out.println("===" + contentLen);
				} else if (line.toLowerCase().startsWith("transfer-encoding")) {
					transferEncoding = getHeaderValue(line, "transfer-encoding:");
					if (transferEncoding != null && transferEncoding.equals("chunked")) {
						isChunked = true;
					}
				} else if (line.toLowerCase().startsWith("content-type")) {
					contentType = getHeaderValue(line, "content-type:");
				} else if (line.toLowerCase().startsWith("content-encoding")) {
					contentEncoding = getHeaderValue(line, "content-encoding:");
					if (contentEncoding != null) {
						gzip = contentEncoding.indexOf("gzip") > 0;
					}
				} else if (line.toLowerCase().startsWith("host")) {
					host = getHeaderValue(line, "host:");
//					System.out.println("host : " + host);
					if (host != null) {
						boolean in = false;
						for (String s : DEST_WHITE_LIST) {
							if (host.toLowerCase().contains(s)) {
								in = true;
							}
						}
						if (!in) {
							return false;
						}
					}
				} else if (isHttpRequest(line.toLowerCase().getBytes())) {
					request = line;
				} else if (line.trim().length() == 0) {
					break;
				}
				
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

//		System.out.println("request : " + host + " " + request);
		//TODO gzip
		
		if (isChunked) {
			System.out.println("========Chunked Not Supported Yet==========");	//TODO
		} else {
//			System.out.println("request content : " + content);
			String content = new String(readData(body));
			request = request.substring(request.indexOf(" ") + 1);
			request = request.substring(0, request.indexOf(" "));
//			String key = host + request;
			String key = request;
			if (content != null && content.length() > 0) {
				key += "?" + content;
			}
//			System.out.println(key);
			sCurrentKey = key;
		}
		return true;
		
	}
	
	public static void readResponse(ArrayList<TcpPack> packs) {

		if (packs.size() == 0) {
			return;
		}
		
		Collections.sort(packs, new Comparator<TcpPack>() {

			@Override
			public int compare(TcpPack o1, TcpPack o2) {
				return (int) (o1.seq - o2.seq);
			}
		});
		
		byte[] body = null;
		if (packs.size() > 0) {
			body = packs.get(0).body;
		}
		
		if (packs.size() > 1) {
			for (int i = 1 ; i < packs.size() ; i++ ){
				byte[] temp = new byte[body.length + packs.get(i).body.length];
				System.arraycopy(body, 0, temp, 0, body.length);
				System.arraycopy(packs.get(i).body, 0, temp, body.length, packs.get(i).body.length);
				body = temp;
//				System.out.println("||||" + new String(body));
			}
		}
		
		int pos = 0;
		int contentLen = 0;
		String transferEncoding = "";
		String contentEncoding = "";
		String contentType = "";
		boolean gzip = false;
		boolean isChunked = false;
		String host = "";
		String request = "";

		ByteArrayInputStream bis = new ByteArrayInputStream(body);
		InputStreamReader isr = new InputStreamReader(bis);
		BufferedReader reader = new BufferedReader(isr);
		while (true) {

			try {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
//				System.out.println("line" + line);
				
				if (line.toLowerCase().startsWith("content-length:")) {
					contentLen = Integer.valueOf(getHeaderValue(line, "content-length:"));
//					System.out.println("===" + contentLen);
				} else if (line.toLowerCase().startsWith("transfer-encoding")) {
					transferEncoding = getHeaderValue(line, "transfer-encoding:");
					if (transferEncoding != null && transferEncoding.equals("chunked")) {
						isChunked = true;
					}
				} else if (line.toLowerCase().startsWith("content-type")) {
					contentType = getHeaderValue(line, "content-type:");
				} else if (line.toLowerCase().startsWith("content-encoding")) {
					contentEncoding = getHeaderValue(line, "content-encoding:");
					if (contentEncoding != null) {
						gzip = contentEncoding.indexOf("gzip") > 0;
					}
				} else if (line.toLowerCase().startsWith("host")) {
					host = getHeaderValue(line, "host:");
					if (host != null) {
						for (String s : DEST_WHITE_LIST) {
							if (!host.toLowerCase().contains(s)) {
								return;
							}
						}
					}
				} else if (isHttpRequest(line.toLowerCase().getBytes())) {
					request = line;
					System.out.println("response : " + line);
				} else if (line.trim().length() == 0) {
					break;
				}
				
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		if (contentType != null && contentType.toLowerCase().startsWith("image")) {
			
			//TODO
//			System.out.println("===image not support yet==");
			sDataMap.put(sCurrentKey, readData(body));
			return;
		}
		
		//TODO gzip
		
		if (isChunked) {
			try {
				ByteArrayInputStream gzipInputStream = new ByteArrayInputStream(readChunkedData(body));
//				System.out.println("==chunked response==" + );	//TODO
				String content = unGzipBytesToString(gzipInputStream);
				sDataMap.put(sCurrentKey, content.getBytes());
			} catch (Exception e) {
				
			}
		} else {

			sDataMap.put(sCurrentKey, readData(body));
		}
		
		
	}
	
	/**
	 * 关闭InputStream
	 */
	public static void closeQuietly(OutputStream os) {
		try {
			if (os != null) {
				os.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 将input流转为byte数组，自动关闭
	 * 
	 * @param input
	 * @return
	 */
	public static byte[] toByteArray(InputStream input) throws Exception {
		if (input == null) {
			return null;
		}
		ByteArrayOutputStream output = null;
		byte[] result = null;
		try {
			output = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024 * 100];
			int n = 0;
			while (-1 != (n = input.read(buffer))) {
				output.write(buffer, 0, n);
			}
			result = output.toByteArray();
		} finally {
			closeQuietly(input);
			closeQuietly(output);
		}
		return result;
	}
	
	public static String unGzipBytesToString(InputStream in) {

		try {
			PushbackInputStream pis = new PushbackInputStream(in, 2);
			byte[] signature = new byte[2];
			pis.read(signature);
			pis.unread(signature);
			int head = ((signature[0] & 0x00FF) | ((signature[1] << 8) & 0xFF00));
			if (head != GZIPInputStream.GZIP_MAGIC) {
				return new String(toByteArray(pis), "UTF-8").trim();
			}
			GZIPInputStream gzip = new GZIPInputStream(pis);
			byte[] readBuf = new byte[8 * 1024];
			ByteArrayOutputStream outputByte = new ByteArrayOutputStream();
			int readCount = 0;
			do {
				readCount = gzip.read(readBuf);
				if (readCount > 0) {
					outputByte.write(readBuf, 0, readCount);
				}
			} while (readCount > 0);
			closeQuietly(gzip);
			closeQuietly(pis);
			closeQuietly(in);
			if (outputByte.size() > 0) {
				return new String(outputByte.toByteArray(), "UTF-8");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	static class HttpConn {
		
		private TcpPack pack;
		private ArrayList<TcpPack> pacList = new ArrayList<PcapUtil.TcpPack>();
		private int status = 0;
		
		public HttpConn(TcpPack pack) {
			this.pack = pack;
		}
		
		public void append(TcpPack toAppend) {
			if (toAppend.body == null) {
				return;
			}
			if (status == -1 || status == 2) {
				return;
			}
			if (!toAppend.source.equals(pack.source)) {
				toAppend.direction = 1;
			}
			
			pacList.add(toAppend);
			
			if (status == 0) {
				if (isHttpRequest(toAppend.body)) {
					status = 1;
				}
			}
			
			if (toAppend.pacType == -1) {
				if (status == 1) {
					status = 2;
				} else {
					status = -2;
				}
			}
			
		}
		
		public void output() {
			
			if (status <= -1) {
				return;
			} else if (status == 0) {
				return;
			}
			
			System.out.println(pack.source + ":" + pack.sourcePort + "-->" + pack.dest + ":" + pack.destPort);
			
			ArrayList<TcpPack> requestPacs = new ArrayList<PcapUtil.TcpPack>();
			ArrayList<TcpPack> responsePacs = new ArrayList<PcapUtil.TcpPack>();
			
			int state = 0;
			for (TcpPack pac : pacList) {
				
				if (pac.body == null || pac.body.length == 0) {
					continue;
				}
				
				if (state == 0) {
					if (pac.direction == 1) {
						boolean cont = readRequest(requestPacs);
						state = 1;
						if (cont) {
							responsePacs.add(pac);
						}
						requestPacs.clear();
					} else {
						requestPacs.add(pac);
					}
				} else {
					if (pac.direction == 0) {
						readResponse(responsePacs);
						state = 0;
						requestPacs.add(pac);
						responsePacs.clear();
					} else {
						responsePacs.add(pac);
					}
				}
				
			}
			
			if (requestPacs.size() > 0) {
				readRequest(responsePacs);
			}
			if (responsePacs.size() > 0) {
				readResponse(responsePacs);
			}
			
			
		}
		
	}
	
	
	public static int getIntFromByteBigEndian(byte[] source, int start) {
		
		int r = ((source[start] << 24) & 0xFF000000) | ((source[start + 1] << 16) & 0x00FF0000) | ((source[start + 2] << 8) & 0x0000FF00) | (source[start + 3] & 0x000000FF);
		return r;
	}
	
	public static int getIntFromByte(byte[] source, int start) {
		
		int r = ((source[start + 3] << 24) & 0xFF000000) | ((source[start + 2] << 16) & 0x00FF0000) | ((source[start + 1] << 8) & 0x0000FF00) | (source[start] & 0x000000FF);
		return r;
	}
	

	public static short getShortFromByteBigEndian(byte[] source, int start) {
		
		short r = (short) (((source[start] << 8) & 0x0000FF00) | (source[start + 1] & 0x000000FF));
		return r;
	}
	
	public static ArrayList<TcpPack> processPcapPackage(InputStream in) throws IOException {
		
		ArrayList<TcpPack> result = new ArrayList<PcapUtil.TcpPack>();
		
		while(true) {
			
			byte[] packageHeader = new byte[16];
			if (in.read(packageHeader) < 0) {
				break;
			}
			int seconds = getIntFromByte(packageHeader, 0);
			int susecondes = getIntFromByte(packageHeader, 4);
			int packageLen = getIntFromByte(packageHeader, 8);
			int rawLen = getIntFromByte(packageHeader, 12);
			
			byte[] ethernetHeader = new byte[14];
			in.read(ethernetHeader);
			short nProtocol = getShortFromByteBigEndian(ethernetHeader, 12);
//			System.out.println(" " + seconds + " " + susecondes + " " + packageLen + " " + rawLen + " " + nProtocol);
			
			if (nProtocol != 2048) {
				in.skip(packageLen - 14);
				continue;
			}
			
			byte[] ipHeader = new byte[20];
			in.read(ipHeader);
			int f = (ipHeader[0] & 0x000000FF);
			int ipLength = getShortFromByteBigEndian(ipHeader, 2);
			int protocol = (ipHeader[9] & 0x000000FF);
			
			int ipHeaderLen = (f & 0x0000000F) * 4;
			int ipVersion = (f >> 4) & 0x0000000F;
			
			if (protocol != 6) {
				in.skip(packageLen - 14 - 20);
				continue;
			}
			
			byte[] sourceBytes = new byte[4];
			System.arraycopy(ipHeader, 12, sourceBytes, 0, 4);
			String source = InetAddress.getByAddress(sourceBytes).getHostAddress();
			
			byte[] destBytes= new byte[4];
			System.arraycopy(ipHeader, 16, destBytes, 0, 4);
			String dest = InetAddress.getByAddress(destBytes).getHostAddress();
			
			if (ipHeaderLen > 20) {
				sIn.skip(ipHeaderLen - 20);
			}
			
			byte[] tcpHeader = new byte[20];
			sIn.read(tcpHeader);
			int sourcePort = (getShortFromByteBigEndian(tcpHeader, 0) & 0xFFFF);
			int destPort = (getShortFromByteBigEndian(tcpHeader, 2) & 0xFFFF);
			
			
			long seq = ((getIntFromByteBigEndian(tcpHeader, 4)) & 0x0FFFFFFFFl);
			long ack_seq = ((getIntFromByteBigEndian(tcpHeader, 8)) & 0x0FFFFFFFFl);
			int t_f = (tcpHeader[12] & 0x000000FF);
			int flags = (tcpHeader[13] & 0x000000FF);
			
			int tcpHeaderLen = ((t_f >> 4) & 0xF) * 4;
			if (tcpHeaderLen > 20) {
				sIn.skip(tcpHeaderLen - 20);
			}
			
			int fin = flags & 1;
			int syn = (flags >> 1) & 1;
			int rst = (flags >> 2) & 1;
			int psh = (flags >> 3) & 1;
			int ack = (flags >> 4) & 1;
			int urg = (flags >> 5) & 1;
			
			int bodyLen = packageLen - 14 - ipHeaderLen - tcpHeaderLen;
			int bodyLen2 = ipLength - ipHeaderLen - tcpHeaderLen;
			
			byte[] body = new byte[bodyLen2];
			sIn.read(body);
			
			if (bodyLen > bodyLen2) {
				sIn.skip(bodyLen - bodyLen2);
			}
			
			int pacType = 0;
			if (syn == 1 && ack == 0) {
				pacType = 1;
			} else if (fin == 1) {
				pacType = -1;
			}
			
			result.add(new TcpPack(source, sourcePort, dest, destPort, pacType, seq, ack, body));
			
		}
		return result;
		
	}
	
	public static void closeQuietly(InputStream in) {
		try {
			in.close();
		} catch (Exception e) {
			
		}
	}
	
	/**
	 * check header
	 * @param file
	 * @return
	 * @throws IOException 
	 */
	public static CheckResult checkPcap(File file) throws IOException {
		CheckResult result = new CheckResult();
		result.valid = false;
		result.bigEndian = false;
		if (sIn != null) {
			closeQuietly(sIn);
		}
		sIn = new FileInputStream(file);
//		PushbackInputStream pio = new PushbackInputStream(in);
		
		byte[] globalHead = new byte[24];
		if (sIn.available() >= 24) {
			sIn.read(globalHead);
//			pio.unread(globalHead);
			byte[] magic = new byte[4];
			System.arraycopy(globalHead, 0, magic, 0, 4);
			int magicInt = (((magic[3] << 24) & 0xFF000000) | ((magic[2] << 16) & 0x00FF0000) | ((magic[1] << 8) & 0x0000FF00) | (magic[0] & 0x000000FF));
			if (magicInt == PCAP_MAGIC_NUM) {
				result.valid = true;
			}
			
			System.out.println("==" + magicInt + " " + PCAP_MAGIC_NUM);
			System.out.println("=1=" + ((PCAP_MAGIC_NUM & 0xFF000000) >> 24));
			System.out.println("=1=" + ((PCAP_MAGIC_NUM & 0x00FF0000)));
			System.out.println("=21=" + (((magic[3] << 24) & 0xFF000000) | (magic[2] << 16) & 0x00FF0000));
			System.out.println("=2=" + ((magic[2] << 16) & 0x00FF0000));
			magic[0] = (byte) 0x000000D4;
			System.out.println(" " + magic[0] + " " + magic[1] + " " + magic[2] + " " + magic[3]);
			System.out.println("byte " + globalHead);
//			byte[] magicNumber = globalHead[0 : 4];
			
			
		} else {
			result.valid = false;
		}
		
		return result;
	}

}
