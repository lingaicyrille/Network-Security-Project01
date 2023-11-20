//Cyrille Lingai Dro & Ronald Choque
//CS3750
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
	private static final int HASH_BUFFER_SIZE = 32 * 1024;
	private static final int RSA_BUFFER_SIZE = 128;
	private static final String IV = "AAAAAAAAAAAAAAAA";
	
	public static void main(String[] args) {	
	    try {
	    	//load private key and symmetric key
			PrivateKey keyYPrivate = readPrivKeyFromFile("YPrivate.key");
			String keyXY = getSymmetricKey("symmetric.key");
			
			//get name of file to save decrypted message as
			System.out.println("Input the name of the message file:");
			
			Scanner input = new Scanner(System.in);
			String fileName = input.next();
			input.close();

		    //load rsa encrypted file
			byte[] rsaDecrypted = decryptRSA("message.rsacipher", keyYPrivate);
		    
			saveFileBinary(rsaDecrypted, "message.add-msg");
		 
		    //copy and split decrypted RSA into the encrypted MD and message arrays
		    byte[] encryptedMD = new byte[32];
		    byte[] message = new byte[rsaDecrypted.length - 32];
		    System.arraycopy(rsaDecrypted, 0, encryptedMD, 0, 32);
		    System.arraycopy(rsaDecrypted, 32, message, 0, rsaDecrypted.length - 32);
		    
		    //do AES decryption
			byte[] decryptedMD = decryptAES(keyXY, encryptedMD);
			
			System.out.println("decrypted (AES) md (hash value):");
			
			//Print and save decrypted MD
			printBytes(decryptedMD);
			
			saveFileBinary(decryptedMD, "message.dd");
			
			//calculate SHA256 of message and print
			byte[] md = getSha256(message);
			
			printBytes(md);
			
			//Check if MDs of decrypted and calculated match
			if( checkMDsMatch(md, decryptedMD) ) 
				System.out.println("Authentication Check: PASSED! :-)");
			else
				System.out.println("Authentication Check: FAILED!!! :-(");
			
			
			
			//check if message looks like it is a text or binary file
			if( looksLikeUTF8(message) ) {
				saveFileText(message, fileName);
				//only display message if its text and less than 500 characters
				if( message.length < 500 )
					System.out.println("Message =" + new String(message));
			} else
				saveFileBinary(message, fileName);
			
		    
		    System.out.println("Done!");
			
		} catch (Exception e) {
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

	    InputStream in = new FileInputStream(keyFileName);
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
	
	//read the symmetric key from file
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
	
	//calculate SHA256 of byte array
	public static byte[] getSha256(byte[] message) throws NoSuchAlgorithmException, IOException {
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    ByteArrayInputStream byteStream = new ByteArrayInputStream(message);
	    DigestInputStream in = new DigestInputStream(byteStream, md);
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
	
	//save as binary file
	public static void saveFileBinary(byte[] byteArray, String fileName) throws IOException {
		System.out.println("Saving to binary file: " + fileName);
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
	
	//save as text file
	public static void saveFileText(byte[] byteArray, String fileName) throws IOException {
		System.out.println("Saving to text file: " + fileName);
		System.out.println();
		
		String byteString = new String(byteArray);
		
		PrintWriter pw = new PrintWriter(fileName);
	    
	    try {
	    	pw.write(byteString);
	    } catch (Exception e) {
	      throw new IOException("Unexpected error", e);
	    } finally {
	    	pw.flush();
	    	pw.close();
	    }
	}
	
	//do AES decryption
	public static byte[] decryptAES(String decryptionKey, byte[] encryptedBytes) throws Exception {
		//prepare the cipher
	    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	    SecretKeySpec key = new SecretKeySpec(decryptionKey.getBytes("UTF-8"), "AES");
	    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
	    
	    byte[] plainBytes = new byte[0];
		byte[] readBytes = new byte[16];
		byte[] decryptReadBytes = new byte[16];
	    
	    //loop through encrypted bytes
	    for( int i=0; i<encryptedBytes.length; i=i+16) {
	    	//read 16 bytes at a time
	    	for( int j=0; j<16 && j+i<encryptedBytes.length; j++ ) {
	    		readBytes[j] = encryptedBytes[j+i];
	    	}
	    	//decrypt the 16 bytes
	    	decryptReadBytes = cipher.doFinal(readBytes);
	    	
	    	//copy existing and new bytes into new array
	    	byte[] temp = new byte[i+16];
	    	
	    	if( i != 0 )
	    		System.arraycopy(plainBytes, 0, temp, 0, plainBytes.length);
	    	System.arraycopy(decryptReadBytes, 0, temp, plainBytes.length, decryptReadBytes.length);
	    	
	    	plainBytes = temp;
	    }
	    
	    return plainBytes;
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
	
	//display byte array to screen
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
	
	//do RSA decryption
	public static byte[] decryptRSA(String fileName, PrivateKey privKey) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
			, IllegalBlockSizeException, BadPaddingException, IOException {
		
		//read file
		byte[] encrypted = readFileBytes(fileName);
		
		//prepare cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
				
		byte[] decrypted = new byte[0];
		
		//for entire encrypted file
		for( int i=0; i*RSA_BUFFER_SIZE<encrypted.length; i++ ) {
			//prepare to load 128 bytes, or less if needed
			byte[] temp = new byte[RSA_BUFFER_SIZE];
			if( encrypted.length - RSA_BUFFER_SIZE*i < RSA_BUFFER_SIZE ) {
				temp = new byte[encrypted.length - RSA_BUFFER_SIZE*i];
			}
			
			//load 128 bytes at a time
			for( int j=0; j<temp.length; j++ ) {
				temp[j] = encrypted[j+RSA_BUFFER_SIZE*i] ;	
			}
			//decrypt 128 bytes
			byte[] decipheredTemp = cipher.doFinal(temp);

			//copy existing and new bytes into new array
			byte[] copyTemp = new byte[decrypted.length+decipheredTemp.length];
			
			if( i != 0 )
	    		System.arraycopy(decrypted, 0, copyTemp, 0, decrypted.length);
	    	System.arraycopy(decipheredTemp, 0, copyTemp, decrypted.length, decipheredTemp.length);
	    	decrypted = copyTemp;  	
		}
		
		return decrypted;
	}
	
	//returns true if both provided byte array MD's match
	public static boolean checkMDsMatch(byte[] aMD, byte[] bMD) {
		if( aMD.length != bMD.length )
			return false;
		
		for(int i=0; i<aMD.length; i++) {
			if( aMD[i] != bMD[i] )
				return false;
		}
		return true;
	}
	
	//function from stackoverflow to assist in detecting if a byte array if text or binary
	// https://stackoverflow.com/questions/1193200/how-can-i-check-whether-a-byte-array-contains-a-unicode-string-in-java
	public static boolean looksLikeUTF8(byte[] utf8) throws UnsupportedEncodingException 
	{
		if( utf8.length > 100 ) {
			byte[] temp = new byte[100];
			System.arraycopy(utf8, 0, temp, 0, 100);
			utf8 = temp;
		}
			
	  Pattern p = Pattern.compile("\\A(\n" +
	    "  [\\x09\\x0A\\x0D\\x20-\\x7E]             # ASCII\\n" +
	    "| [\\xC2-\\xDF][\\x80-\\xBF]               # non-overlong 2-byte\n" +
	    "|  \\xE0[\\xA0-\\xBF][\\x80-\\xBF]         # excluding overlongs\n" +
	    "| [\\xE1-\\xEC\\xEE\\xEF][\\x80-\\xBF]{2}  # straight 3-byte\n" +
	    "|  \\xED[\\x80-\\x9F][\\x80-\\xBF]         # excluding surrogates\n" +
	    "|  \\xF0[\\x90-\\xBF][\\x80-\\xBF]{2}      # planes 1-3\n" +
	    "| [\\xF1-\\xF3][\\x80-\\xBF]{3}            # planes 4-15\n" +
	    "|  \\xF4[\\x80-\\x8F][\\x80-\\xBF]{2}      # plane 16\n" +
	    ")*\\z", Pattern.COMMENTS);

	  String phonyString = new String(utf8, "ISO-8859-1");
	  return p.matcher(phonyString).matches();
	}
}
