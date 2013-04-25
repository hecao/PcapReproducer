package com.hecao.utils;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Set;

import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpServerConnection;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.DefaultHttpServerConnection;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpRequestHandlerRegistry;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;

public class HttpServer {
	
	static HashMap<String, byte[]> sDataMap;
	
	static HashMap<String, String> sReplaceMap = new HashMap<String, String>();
	
	static {
		
		sReplaceMap.put("img.meimeiapp.com", "10.2.124.13:8080");
		
	}

	public static void main(String[] args) throws Exception {
		sDataMap = PcapUtil.getData();
		Thread t = new RequestListenerThread(8080);
		t.setDaemon(false);
		t.start();
	}

	static class HttpHandler implements HttpRequestHandler {

		public HttpHandler() {
			super();
		}

		public void handle(final HttpRequest request,
				final HttpResponse response, final HttpContext context)
				throws HttpException, IOException {
			
			System.out.println("request : " + request.getRequestLine().getUri() + " " + request.getRequestLine().toString());
			
			String content = "null";
			
			Set<String> keySet = sDataMap.keySet();
			for (String key : keySet) {
				if (key != null && key.toLowerCase().startsWith(request.getRequestLine().getUri().toLowerCase())) {
					
					byte[] data = sDataMap.get(key);
					if (data != null) {

						if (key.toLowerCase().endsWith("jpg") || key.toLowerCase().endsWith("png")) { //TODO replace with MIME type.

							response.setHeader("ContentType", "image/JPEG");
							ByteArrayEntity entity = new ByteArrayEntity(data);
							response.setEntity(entity); 
							return;
						} else {
							content = new String(data, "UTF-8");
							
							Set<String> toReplace = sReplaceMap.keySet();
							for (String r : toReplace) {
								content = content.replace(r, sReplaceMap.get(r));
							}
							System.out.println("data : " + content);

							response.setHeader("ContentType", "text/plain");
							StringEntity entityTest = new StringEntity(content, "UTF-8");
							entityTest.setContentEncoding("UTF-8");
							response.setEntity(entityTest);
							return;
						}
						
					}
				}
			}
		}

	}

	static class RequestListenerThread extends Thread {

		private final ServerSocket serversocket;
		private final HttpParams params;
		private final HttpService httpService;

		public RequestListenerThread(int port)
				throws IOException {
			this.serversocket = new ServerSocket(port);
			this.params = new SyncBasicHttpParams();
			this.params
					.setIntParameter(CoreConnectionPNames.SO_TIMEOUT, 5000)
					.setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE,
							8 * 1024)
					.setBooleanParameter(
							CoreConnectionPNames.STALE_CONNECTION_CHECK, false)
					.setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true)
					.setParameter(CoreProtocolPNames.ORIGIN_SERVER,
							"HttpComponents/1.1");

			// Set up the HTTP protocol processor
			HttpProcessor httpproc = new ImmutableHttpProcessor(
					new HttpResponseInterceptor[] { new ResponseDate(),
							new ResponseServer(), new ResponseContent(),
							new ResponseConnControl() });

			// Set up request handlers
			HttpRequestHandlerRegistry reqistry = new HttpRequestHandlerRegistry();
			reqistry.register("*", new HttpHandler());

			// Set up the HTTP service
			this.httpService = new HttpService(httpproc,
					new DefaultConnectionReuseStrategy(),
					new DefaultHttpResponseFactory(), reqistry, this.params);
		}

		@Override
		public void run() {
			System.out.println("Listening on port "
					+ this.serversocket.getLocalPort());
			while (!Thread.interrupted()) {
				try {
					// Set up HTTP connection
					Socket socket = this.serversocket.accept();
					DefaultHttpServerConnection conn = new DefaultHttpServerConnection();
					System.out.println("Incoming connection from "
							+ socket.getInetAddress());
					conn.bind(socket, this.params);

					// Start worker thread
					Thread t = new WorkerThread(this.httpService, conn);
					t.setDaemon(true);
					t.start();
				} catch (InterruptedIOException ex) {
					break;
				} catch (IOException e) {
					System.err
							.println("I/O error initialising connection thread: "
									+ e.getMessage());
					break;
				}
			}
		}
	}

	static class WorkerThread extends Thread {

		private final HttpService httpservice;
		private final HttpServerConnection conn;

		public WorkerThread(final HttpService httpservice,
				final HttpServerConnection conn) {
			super();
			this.httpservice = httpservice;
			this.conn = conn;
		}

		@Override
		public void run() {
			System.out.println("New connection thread");
			HttpContext context = new BasicHttpContext(null);
			try {
				while (!Thread.interrupted() && this.conn.isOpen()) {
					this.httpservice.handleRequest(this.conn, context);
				}
			} catch (ConnectionClosedException ex) {
				System.err.println("Client closed connection");
			} catch (IOException ex) {
				System.err.println("I/O error: " + ex.getMessage());
			} catch (HttpException ex) {
				System.err.println("Unrecoverable HTTP protocol violation: "
						+ ex.getMessage());
			} finally {
				try {
					this.conn.shutdown();
				} catch (IOException ignore) {
				}
			}
		}

	}

}