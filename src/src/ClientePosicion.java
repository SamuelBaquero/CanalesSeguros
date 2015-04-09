package src;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.crypto.*;
import javax.security.auth.x500.X500Principal;

public class ClientePosicion {
	/**
	 * Constantes.
	 */
	static String DIRSERV = "infracomp.virtual.uniandes.edu.co";
	static int PUERTO = 443;
	static String INIC = "HOLA";
	static String ALG = "ALGORITMOS";
	static String CERTIFICADO = "CERCLNT";
	static String ALGS = "AES";
	static String ALGA = "RSA";
	static String ALGD = "HMACSHA1";
	static String SG = ":";
	static KeyPair keypair;

	/**
	 * Variables.
	 */
	static Socket comunicacion;
	static PrintWriter writer;
	static BufferedReader reader;
	static String certServer = null;

	/**
	 * Codigo.
	 * @param args
	 */
	public static void main(String args[]){
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
			//HOLA
			writer.println( INIC );
			//INICIO
			System.out.println(reader.readLine());
			//ALGORITMOS:ALGS:ALGA:ALGD
			writer.println( ALG + SG + ALGS + SG + ALGA + SG + ALGD);
			if(reader.ready()) System.out.println(reader.readLine());
			//ESTADO:OK|ERROR
			System.out.println(reader.readLine());
			//CERCLNT
			writer.println( CERTIFICADO );
			//FLUJO DE BYTES DEL CERTIFICADO
			/*CREACION DEL CERTIFICADO*/
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
			X509Certificate cert  = certGen.generate(keypair.getPrivate(), "BC");
			byte[] certb = cert.getEncoded();
			/*ENVIO DE INFORMACION*/
			comunicacion.getOutputStream().write(certb);
			comunicacion.getOutputStream().flush();
			//CERSRV
			System.out.println(reader.readLine());
			//FLUJO DE BYTES DEL CERTIFICADO
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			Certificate certs = cf.generateCertificate(comunicacion.getInputStream());
			//INIT
			String[] in = reader.readLine().split(":");
			System.out.println(in[0]);
			String llaveSimetrica = in[1];
			//ACTV
			
			//ACT2
			//RTA:OK|ERROR
		}catch(IOException e){
			System.out.println("Error en la conexion con el servidor: "+e.getMessage());
		} catch (CertificateEncodingException e) {
			System.out.println("Error en el certificado: "+e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en generando las llaves: "+e.getMessage());
		} catch (InvalidKeyException | IllegalStateException | NoSuchProviderException | SignatureException e) {
			System.out.println("Error firmando el certificado " + e.getMessage());
		} catch (CertificateException e) {
			System.out.println("Error en el certificado");
		}finally{
			try {
				comunicacion.close();
				writer.close();
				reader.close();
			} catch (IOException e) {
				System.out.println("No se pudo cerrar la conexion." + e.getMessage());
			}
		}
	}
}
