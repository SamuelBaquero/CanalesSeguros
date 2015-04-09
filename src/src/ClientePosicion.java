package src;

import java.io.*;
import java.io.ObjectInputStream.GetField;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public class ClientePosicion {
	/**
	 * Variables de configuracion y comunicacion con el servidor..
	 */
	//Direccion de conexion con el servidor.
	private static String DIRSERV = "infracomp.virtual.uniandes.edu.co";
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
	 * Socket.
	 */
	//Socket para la comunicacion.
	private static Socket comunicacion;
	//Writer para escritura sobre el socket.
	private static PrintWriter writer;
	//Reader para lectura sobre el socket.
	private static BufferedReader reader;

	/**
	 * Codigo.
	 * @param args
	 */
	public static void main(String args[]){
		inicializar();
		//HOLA, INICIO, ALGORITMOS, ESTADO
		inicio();
		//CERTIFICADO DEL CLIENTE
		enviarCertificado();
		//CERTIFICADO DEL SERVIDOR
		recibirCertificado();
		//INIT, LLAVE SIMETRICA
		init();
		//ACT Usar la llave Simetrica o de sesion para codificar la posicion.

		//ACT Usar la llave Simetrica para la funcion de hash y luego cifrar con la publica del servidor.

		//RTA:OK|ERROR
		//CIERRE DE CONEXION CON EL SERVIDOR
		cerrarConexion();
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
			comunicacion = new Socket("localhost", PUERTO);
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
}
