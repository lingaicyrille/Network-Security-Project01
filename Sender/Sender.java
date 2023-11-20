//Cyrille Lingai Dro & ronald choque
//CS3750
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Sender {
	private static final int HASH_BUFFER_SIZE = 32 * 1024;
	private static final int RSA_BUFFER_SIZE = 117;
	private static final String IV = "AAAAAAAAAAAAAAAA";
	
	public static void main(String[] args) {
	    try {    	
	    	//load public key and symmetric key
			PublicKey keyYPublic = readPubKeyFromFile("YPublic.key");
			String keyXY = getSymmetricKey("symmetric.key");
			
			//load file to be encrypted
			System.out.println("Input the name of the message file:");
			
			Scanner input = new Scanner(System.in);
			String fileName = input.next();
			
			//read file in as our message
			byte[] message = readFileBytes(fileName);
			
			//calculate SHA256 as md
			byte[] md = getSha256(fileName);
			
			//ask if want to invert first byte for testing
			System.out.println("Do you want to invert  the first byte in SHA256(M)? ( Y or N )");
			
			String entry = input.next();
			input.close();
			
			if( entry.equalsIgnoreCase("y") ) {
				md[0] = (byte)~ md[0];
			}else if( !entry.equalsIgnoreCase("n") ) {
				System.out.println("Invalid option, I quit");
				return;
			}
			

			//display and save the hash md
			System.out.println("md (hash value):");
		    printBytes(md);
			
			saveFile(md, "message.dd");
			
			//do AES encryption
			byte[] encryptedMD = encryptAES(keyXY, md);
			
			System.out.println("encrypted (AES) md (hash value):");
			printBytes(encryptedMD);
			
			//combine encryptedMD and message into single array
		    byte[] addMsg = new byte[encryptedMD.length+message.length];
		    System.arraycopy(encryptedMD, 0, addMsg, 0, encryptedMD.length);
		    System.arraycopy(message, 0, addMsg, encryptedMD.length, message.length);
		    
		    //save encryptedMD and message to file
		    saveFile(addMsg, "message.add-msg");
		    
		    //load addMsg file (redundant?)
		    byte[] rsaMsg = readFileBytes("message.add-msg");
		    
		    //do RSA encryption
		    byte[] rsaEncrypted = encryptRSA(rsaMsg, keyYPublic);
		    
		    //save final encrypted RSA to file
		    saveFile(rsaEncrypted, "message.rsacipher");
		    
		    System.out.println("Done!");
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	}

	//read key parameters from a file and generate the public key 
	public static PublicKey readPubKeyFromFile(String keyFileName) 
	      throws IOException {

	    FileInputStream in = 
	    		new FileInputStream(keyFileName);
	    ObjectInputStream oin =
	        new ObjectInputStream(new BufferedInputStream(in));

	    try {
	      BigInteger m = (BigInteger) oin.readObject();
	      BigInteger e = (BigInteger) oin.readObject();

	      System.out.println("Read from " + keyFileName + ": modulus = " + 
	          m.toString() + ", exponent = " + e.toString() + "\n");

	      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
	      KeyFactory factory = KeyFactory.getInstance("RSA");
	      PublicKey key = factory.generatePublic(keySpec);

	      return key;
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	    
	      oin.close();
	      in.close();
	    }
	}


	//read key parameters from a file and generate the private key 
	public static PrivateKey readPrivKeyFromFile(String keyFileName) 
	      throws IOException {

	    InputStream in = 
	    		Sender.class.getResourceAsStream(keyFileName);
	    ObjectInputStream oin =
	        new ObjectInputStream(new BufferedInputStream(in));

	    try {
	      BigInteger m = (BigInteger) oin.readObject();
	      BigInteger e = (BigInteger) oin.readObject();

	      System.out.println("Read from " + keyFileName + ": modulus = " + 
	          m.toString() + ", exponent = " + e.toString() + "\n");

	      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
	      KeyFactory factory = KeyFactory.getInstance("RSA");
	      PrivateKey key = factory.generatePrivate(keySpec);

	      return key;
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	      oin.close();
	    }
	}
	
	//Loads the symmetric key from binary file
	public static String getSymmetricKey(String fileName) throws IOException {
	    BufferedInputStream symKeyFile = null;

		symKeyFile = new BufferedInputStream(
				new FileInputStream(fileName));
		
		byte[] symKey = symKeyFile.readAllBytes();

	    String symKeyStr = new String(symKey, StandardCharsets.UTF_8);
	    System.out.println("Symmetric Key=" + symKeyStr);
	    	
	    
		symKeyFile.close();
		return symKeyStr;
	}
	
	//calculate the md SHA256 of file
	public static byte[] getSha256(String fileName) throws NoSuchAlgorithmException, IOException {
	    BufferedInputStream file = new BufferedInputStream(new FileInputStream(fileName));
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    DigestInputStream in = new DigestInputStream(file, md);
	    int i;
	    byte[] buffer = new byte[HASH_BUFFER_SIZE];
	    do {
	      i = in.read(buffer, 0, HASH_BUFFER_SIZE);
	    } while (i == HASH_BUFFER_SIZE);
	    md = in.getMessageDigest();
	    in.close();

	    byte[] hash = md.digest();
   
	    return hash;
	}
	
	//save binary file
	public static void saveFile(byte[] byteArray, String fileName) throws IOException {
		System.out.println("Saving to file: " + fileName);
		System.out.println();
		
		FileOutputStream oout = new FileOutputStream(fileName);
	    try {
	    	oout.write(byteArray);
	    } catch (Exception e) {
	      throw new IOException("Unexpected error", e);
	    } finally {
	      oout.flush();
	      oout.close();
	    }
	}
	
	//do the AES encryption
	public static byte[] encryptAES(String encryptionKey, byte[] plainBytes) throws Exception {
	    //prepare cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
	    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
	    
	    byte[] cipherBytes = new byte[0];
		byte[] readBytes = new byte[16];
		byte[] encryptReadBytes = new byte[16];
	    
	    //loop through all bytes in the message
	    for( int i=0; i<plainBytes.length; i=i+16) {
	    	//load the next 16 bytes and then doFinal on cipher
	    	for( int j=0; j<16 && j+i<plainBytes.length; j++ ) {
	    		readBytes[j] = plainBytes[j+i];
	    	}
	    	encryptReadBytes = cipher.doFinal(readBytes);
	    	
	    	//copy existing array and new bytes into encrypted array
	    	byte[] temp = new byte[i+16];
	    	
	    	if( i != 0 )
	    		System.arraycopy(cipherBytes, 0, temp, 0, cipherBytes.length);
	    	System.arraycopy(encryptReadBytes, 0, temp, cipherBytes.length, encryptReadBytes.length);
	    	
	    	cipherBytes = temp;
	    }
	    
	    return cipherBytes;
	}
	
	//read bytes from file
	public static byte[] readFileBytes(String fileName) throws IOException {	
		FileInputStream in = 
	    		new FileInputStream(fileName);
		
		BufferedInputStream bin = new BufferedInputStream(in);
		
	    try {	      
	    	byte[] message = bin.readAllBytes();
	    	
	    	return message;     
	    } catch (Exception e) {
	      throw new RuntimeException("Spurious serialisation error", e);
	    } finally {
	    	bin.close();
	    }
	}
	
	//display bytes on screen
	public static void printBytes(byte[] bytes) {
		for (int k=0, j=0; k<bytes.length; k++, j++) {
	      System.out.format("%2X ", bytes[k]) ;
	      if (j >= 15) {
	        System.out.println("");
	        j=-1;
	      }
	    }
	    System.out.println(""); 
	}
	
	//do RSA encryption
	public static byte[] encryptRSA(byte[] msg, PublicKey pubKey) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//prepare cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		SecureRandom random = new SecureRandom();
		
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
		byte[] encrypted = new byte[0];
		
		//looping through entire payload
		for( int i=0; i*RSA_BUFFER_SIZE<msg.length; i++ ) {
			//make temp array for 117 bytes, but check if less than remain
			byte[] temp = new byte[RSA_BUFFER_SIZE];
			if( msg.length - RSA_BUFFER_SIZE*i < RSA_BUFFER_SIZE ) {
				temp = new byte[msg.length - RSA_BUFFER_SIZE*i];
			}
		
			//load the next 117 (or less) bytes
			for( int j=0; j<temp.length; j++ ) {
				temp[j] = msg[j+RSA_BUFFER_SIZE*i] ;	
			}
			//do encryption
			byte[] cipheredTemp = cipher.doFinal(temp);

			//copy existing array and new bytes into encrypted array
			byte[] copyTemp = new byte[encrypted.length+cipheredTemp.length];
			
			if( i != 0 )
	    		System.arraycopy(encrypted, 0, copyTemp, 0, encrypted.length);
	    	System.arraycopy(cipheredTemp, 0, copyTemp, encrypted.length, cipheredTemp.length);
	    	encrypted = copyTemp;
		}
		
		return encrypted;
	}
}
