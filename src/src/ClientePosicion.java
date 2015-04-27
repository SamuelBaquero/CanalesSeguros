package src;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public class ClientePosicion {
	
	/**
	 * Variables de medicion de indicadores.
	 */
	private static double iSession;
	private static double iRepo;
	private static int iFallo;
	
	/**
	 * Variables de configuracion y comunicacion con el servidor..
	 */
	//Direccion de conexion con el servidor.
	private static String DIRSERV = "localhost";
	//Puerto de conexion.
	private static int PUERTO = 443;
	//Mensaje inicial
	private static String INIC = "HOLA";
	//Mensaje de aviso de envio de los algoritmos.
	private static String ALG = "ALGORITMOS";
	//Mensaje de aviso de envio del certificado.
	private static String CERTIFICADO = "CERCLNT";
	//Algoritmo simetrico a usar.
	private static String ALGS = "AES";
	//Algoritmo asimetrico a usar.
	private static String ALGA = "RSA";
	//Algoritmo HASH a usar.
	private static String ALGD = "HMACSHA1";
	//Separador general de los mensajes.
	private static String SG = ":";
	
	/**
	 * Variables de seguridad.
	 */
	//Par de llaves propias, publica y privada.
	private static KeyPair keypair;
	//Certificado propio.
	private static X509Certificate cert;

	//Certificado del servidor.
	private static Certificate certs;
	//Llave de sesion simetrica.
	private static SecretKey sessionKey;

	/**
	 * Variables de informacion.
	 */
	private static int gradInt = 41;
	private static double gradDouble = 24.2028;
	private static int minInt = 2;
	private static double minDouble = 10.4418;
	private static String posicion = gradInt+" "+gradDouble+","+minInt+" "+minDouble;
	
	/**
	 * Socket.
	 */
	//Socket para la comunicacion.
	private static Socket comunicacion;
	//Writer para escritura sobre el socket.
	private static PrintWriter writer;
	//Reader para lectura sobre el socket.
	private static BufferedReader reader;

	/**
	 * Variables de soporte para transformacion de mensajes a Hexa.
	 */
	private static char[] HEX_CHARS = "0123456789abcdef".toCharArray();
	
	/**
	 * Codigo.
	 * @param args
	 */
	public static void main(String args[]){
		new ClientePosicion();
	}
	
	public ClientePosicion(){
		iRepo = System.currentTimeMillis();
		iSession = iRepo;
		inicializar();
		//HOLA, INICIO, ALGORITMOS, ESTADO
		inicio();
		//CERTIFICADO DEL CLIENTE
		enviarCertificado();
		//CERTIFICADO DEL SERVIDOR
		recibirCertificado();
		//INIT, LLAVE SIMETRICA
		init();
		iSession = System.currentTimeMillis()-iSession;
		//ACT
		enviarPosicion();
		//ACT2
		enviarHashPosicion();
		//RTA:OK|ERROR
		respuesta();
		iRepo = System.currentTimeMillis()-iRepo;
		//CIERRE DE CONEXION CON EL SERVIDOR
		cerrarConexion();
		generarReporte();
	}

	/**
	 * Inicialización de variables, llaves y librerías.
	 * Inicia el socket de comunicación.
	 * Genera las llaves simétricas propias.
	 * Añade el proveedor de seguridad de la librería BouncyCastle.
	 */
	private static void inicializar(){
		try{
			Security.addProvider(new BouncyCastleProvider());
			//Inicializacion de las llaves.
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGA);
			generator.initialize(1024);
			keypair = generator.generateKeyPair();
			//Inicializacion de los sockets
			comunicacion = new Socket(DIRSERV, PUERTO);
			writer = new PrintWriter(comunicacion.getOutputStream(), true);
			reader = new BufferedReader(new InputStreamReader(comunicacion.getInputStream()));
		}catch(Exception e){
			System.out.println("Error en la inicializacion del cliente: " + e.getMessage());
		}
	}

	/**
	 * Inicia la comunicacion con el servidor, envia los algoritmos a usar y recibe el estado del servidor.
	 */
	private static void inicio(){
		try{
			//HOLA
			writer.println( INIC );
			//INICIO
			System.out.println(reader.readLine());
			//ALGORITMOS:ALGS:ALGA:ALGD
			writer.println( ALG + SG + ALGS + SG + ALGA + SG + ALGD);
			if(reader.ready()) System.out.println(reader.readLine());
			//ESTADO:OK|ERROR
			System.out.println(reader.readLine());
		}catch(Exception e){
			System.out.println("Error en el envio de algoritmos: "+e.getMessage());
		}

	}

	/**
	 * Crea y envia el certificado propio al servidor
	 */
	private static void enviarCertificado(){
		//CERCLNT
		writer.println( CERTIFICADO );
		/*PREPARACION DEL CERTIFICADO*/
		Date startDate = new Date (System.nanoTime());
		Date expiryDate = new Date (System.nanoTime() + 999999999);
		BigInteger serialNumber = new BigInteger("1909199426091995");
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);
		certGen.setPublicKey(keypair.getPublic());
		certGen.setSignatureAlgorithm("MD2with"+ALGA);
		try{
			/*GENERADO DEL CERTIFICADO*/
			cert  = certGen.generate(keypair.getPrivate(), "BC");
			byte[] certb = cert.getEncoded();
			/*ENVIO DE INFORMACION*/
			comunicacion.getOutputStream().write(certb);
			comunicacion.getOutputStream().flush();
		}catch(Exception e){
			System.out.println("Error en la creacion y envio del certificado: " + e.getMessage());
		}
	}

	/**
	 * Recibe el certificado de identificacion del servidor.
	 */
	private static void recibirCertificado(){
		try{
			//CERSRV
			System.out.println(reader.readLine());
			//FLUJO DE BYTES DEL CERTIFICADO
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			certs = cf.generateCertificate(comunicacion.getInputStream());
		}catch(Exception e){
			System.out.println("Error recibiendo el certificado del servidor: "+e.getMessage());
		}
	}

	/**
	 * Recibe el mensaje de inicio de comunicacion, saca la llave de sesion y la guarda en una variable.
	 */
	private static void init(){
		String[] in;
		try {
			in = reader.readLine().split(":");
			System.out.println(in[0]);
			/*Para decodificar la llave toca pasarla a hexa y luego decodificarla con la privada propia*/
			Cipher cip = Cipher.getInstance(ALGA);
			cip.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
			byte[] hexaMessage = cip.doFinal(DatatypeConverter.parseHexBinary(in[1]));

			sessionKey = new SecretKeySpec(hexaMessage, 0, hexaMessage.length, ALGS);
		} catch (Exception e) {
			System.out.println("Error en la obtencion de la llave simetrica del servidor: " + e.getMessage());
		}
	}

	/**
	 * Envia la posicion cifrada con la llave de sesion.
	 */
	private static void enviarPosicion(){
		// Usar la llave Simetrica o de sesion para codificar la posicion.
		try {
			Cipher cip = Cipher.getInstance(ALGS);
			cip.init(Cipher.ENCRYPT_MODE, sessionKey);
			byte[] buf = cip.doFinal(posicion.getBytes());
			char[] chars = new char[2 * buf.length];
			for (int i = 0; i < buf.length; ++i)
			{
				chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
				chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
			}
			writer.println("ACT1:"+new String(chars));
		} catch (Exception e) {
			System.out.println("Error cifrando y enviando la posicion: "+e.getMessage());
		}
	}

	/**
	 * Envia la posicion cifrada con un algoritmo de hash.
	 */
	private static void enviarHashPosicion(){
		try{
			//Funcion de Hash "HmacSHA1" sobre la posicion.
			Mac mac = Mac.getInstance(ALGD);
			mac.init(sessionKey);
			byte[] hpos = mac.doFinal(posicion.getBytes());
			//Encriptado simetrico con la llave publica del servidor.
			Cipher cip = Cipher.getInstance(ALGA);
			cip.init(Cipher.ENCRYPT_MODE, certs.getPublicKey());
			byte[] hposcif = cip.doFinal(hpos);
			//Transformacion a hexa.
			char[] chars = new char[2 * hposcif.length];
			for (int i = 0; i < hposcif.length; ++i)
			{
				chars[2 * i] = HEX_CHARS[(hposcif[i] & 0xF0) >>> 4];
				chars[2 * i + 1] = HEX_CHARS[hposcif[i] & 0x0F];
			}
			//Envio de informacion por el servidor.
			writer.println("ACT2:"+new String(chars));
		}catch(Exception e){
			System.out.println("Error enviando el hash de la posicion: "+e.getMessage());
		}
	}

	/**
	 * Recibe la respuesta final del servidor.
	 * OK si funciono, ERROR de lo contrario.
	 */
	private static void respuesta(){
		try {
			String r = reader.readLine();
			System.out.println(r);
			if(r.equals("OK")){
				iFallo = 0;
			}else if(r.equals("ERROR")){
				iFallo = 1;
			}
		} catch (Exception e) {
			System.out.println("Error en la respuesta final del servidor: " + e.getMessage());
		}
	}

	/**
	 * Cierra la conexion con el socket de comunicacion.
	 */
	private static void cerrarConexion(){
		try{
			writer.close();
			reader.close();
			comunicacion.close();
		}catch(Exception e){
			System.out.println("Error cerrando la conexion con el servidor: " + e.getMessage());
		}
	}
	
	/**
	 * Añade a un excel el reporte de tiempos de ejecucion.
	 */
	private static void generarReporte() {
		try {
			System.out.println(iSession);
			System.out.println(iRepo);
			System.out.println(iFallo);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
