package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
    	System.out.println("AES with CTR mode : \n");
    	
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
              //Send and receive 10 messages
            	for(int i=1; i<=10; i++)
            	{
            		///////////// Sending /////////////
                	Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding"); //Encryption with AES in CBR
                	encrypt.init(Cipher.ENCRYPT_MODE, key); //initializing the encryption mode with the key
                	byte[] iv = encrypt.getIV(); //getting the iv
                	
                    final String message = "I love you Bob x"+ i + " times. Kisses, Alice."; // message to send to bob
                    final byte[] messageBytes = message.getBytes(); //converting the previous message in bytes
                    final byte[] cipherText = encrypt.doFinal(messageBytes); // doing encryption with the Cipher class
                    send("bob", iv); //send the IV
                    send("bob", cipherText); //send the cipher text
                    
                    ////////////// Receiving //////////////
                	byte[] ivReceived = receive("bob"); //First we get the iv
                	byte[] ctReceived = receive("bob"); //Then the cipher text 
                	
                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding"); //Instantiate Cipher class with AES in CBR
                    IvParameterSpec ivSpec = new IvParameterSpec(ivReceived); //Creating IvParameterSpec with the iv we received from Alice
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec); //Decryption of the message
                    
                    final byte[] dt = decrypt.doFinal(ctReceived); //We get the message in bytes
                    final String pt = new String(dt); //We get the plain text
                    
                    print("Got : '%s'", pt); 
                  
            	}
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
            	//Send and receive 10 messages
            	for(int i=1; i<=10; i++)
            	{
                	////////////// Receiving //////////////
                	byte[] iv = receive("alice"); //First we get the iv
                	byte[] ct = receive("alice"); //Then the cipher text 
                	
                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding"); //Instantiate Cipher class with AES in CBR
                    IvParameterSpec ivSpec = new IvParameterSpec(iv); //Creating IvParameterSpec with the iv we received from Alice
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec); //Decryption of the message
                    
                    final byte[] dt = decrypt.doFinal(ct); //We get the message in bytes
                    final String pt = new String(dt); //We get the plain text
                    
                    print("Got : '%s'", pt); 
                	
                	///////////// Sending /////////////  
                	Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding"); //Encryption with AES in CBR
                	encrypt.init(Cipher.ENCRYPT_MODE, key); //initializing the encryption mode with the key
                	byte[] ivSend = encrypt.getIV(); //getting the iv
                	
                    final String messageFromBob = "I love you too Alice x" +i + " times, Bob."; // message to send to bob
                    final byte[] messageBytesFromBob = messageFromBob.getBytes(); //converting the previous message in bytes
                    final byte[] cipherTextFromBob = encrypt.doFinal(messageBytesFromBob); // doing encryption with the Cipher class
                    send("alice", ivSend); //send the IV
                    send("alice", cipherTextFromBob); //send the cipher text
            	}
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
