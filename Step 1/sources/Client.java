import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    public static final String provider = "SunJCE";

    public static void main(String[] args) {        
        System.out.println("Provider: " + provider);

        String server = "localhost";
        int port = 8888;

        if(args.length > 0){
            System.out.println("Arguments: " + Arrays.toString(args));

            for(int i = 0; i < args.length; i++){
                if(args[i].equals("--destination") && i + 1 < args.length){
                    System.out.println("Server: " + args[i + 1]);
                    server = args[i + 1];
                }

                if(args[i].equals("--dport") && i + 1 < args.length){
                    System.out.println("Port: " + args[i + 1]);
                    port = Integer.parseInt(args[i + 1]);
                }
            }
        }        
        System.out.println("Connecting to " + server + ":" + port);


        Socket socket;
        try {
            socket = new Socket(server,port);
            socket.setTcpNoDelay(true);
            System.out.println("Connected to " + socket.getRemoteSocketAddress());

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            String r1 = in.readLine();
            System.out.println("Server - message: " + r1);

            SecureRandom random = new SecureRandom();
            KeyGenerator kg = KeyGenerator.getInstance("DESede", provider);
            kg.init(random);

            SecretKey key = kg.generateKey();
            System.out.println("Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
            out.write(Base64.getEncoder().encodeToString(key.getEncoded()) + "\r\n");
            out.flush();

            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            String r2 = in.readLine();
            System.out.println("Server - sent text to crypt: " + r2);

            byte[] r2BytesCiphered = cipher.doFinal(r2.getBytes());
            System.out.println("Client - crypted message: " + Base64.getEncoder().encodeToString(r2BytesCiphered));

            out.write(Base64.getEncoder().encodeToString(r2BytesCiphered) + "\r\n");
            out.flush();
            
            System.out.println("=====================================");    

            String key64 = in.readLine();
            String iv64 = in.readLine();
            String aad = in.readLine();
            String em64 = in.readLine();
            

            System.out.println("Received Key B64: " + key64);
            System.out.println("Received IV B64: " + iv64);
            System.out.println("Received AAD STR: " + aad);
            System.out.println("Received Encrypted Message B64: " + em64);

            byte[] aesKey = Base64.getDecoder().decode(key64);
            byte[] iv = Base64.getDecoder().decode(iv64);
            byte[] em = Base64.getDecoder().decode(em64); 

            Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding",provider);
            decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
            decrypt.updateAAD(aad.getBytes(StandardCharsets.UTF_8));

            byte[] bdm = decrypt.doFinal(em);
            String dm = new String(bdm, StandardCharsets.UTF_8);
            System.out.println("=====================================");    
            System.out.println("Decrypted message: " + dm);

            out.write(dm + "\r\n");
            out.flush();

            socket.close();
            System.out.println("Disconnected from " + socket.getRemoteSocketAddress());

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}