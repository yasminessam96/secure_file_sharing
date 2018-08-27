package sample;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Arrays;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class Controller {
    @FXML
    TextField keyText;
    @FXML
    TextField keyText1;
    @FXML
    TextField fileField1;
    @FXML
    TextField fileField11;
    @FXML
    TextField fileField2;
    @FXML
    TextField fileField21;
    @FXML
    Button encryptKey;
    @FXML
    Button decryptKey;
    @FXML
    Button encryptBtn;
    @FXML
    Button decryptBtn;
    @FXML
    Button chooseBtn;
    SecretKey skey= null;
    byte [] data = new byte[0];
    IvParameterSpec ivspec;

String byteToHexa (byte [] keyBytes ){
       StringBuilder sb = new StringBuilder();
    for (byte b : keyBytes) {
        sb.append(String.format("%02X ", b));
    }
    return sb.toString();
}



    @FXML
    private void encryptFile(ActionEvent event){
        byte[] iv = new byte[128/8];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        ivspec = new IvParameterSpec(iv);
        KeyGenerator kgen = null;
        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        skey = kgen.generateKey();
        byte[] keyBytes= skey.getEncoded();
        Cipher ci = null;
        try {
            ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


        keyText.setText(byteToHexa(keyBytes));
        try (FileInputStream in = new FileInputStream(fileField1.getText());
             FileOutputStream out = new FileOutputStream(fileField11.getText())) {
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = ci.update(ibuf, 0, len);
                if ( obuf != null ) out.write(obuf);
            }
            byte[] obuf = ci.doFinal();
            if ( obuf != null ) out.write(obuf);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
    @FXML
    private void decryptFile(ActionEvent event){
fileDecryption(skey,ivspec);

    }
    public void fileDecryption(SecretKey skey, IvParameterSpec ivspec){
        Cipher ci = null;
        try {
            ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try (FileInputStream in = new FileInputStream(fileField2.getText());
             FileOutputStream out = new FileOutputStream(fileField21.getText())) {
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = ci.update(ibuf, 0, len);
                if ( obuf != null ) out.write(obuf);
            }
            byte[] obuf = ci.doFinal();
            if ( obuf != null ) out.write(obuf);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void encryptKey(ActionEvent event){
         data = RSAEncryption(skey);
    }

    @FXML
    private void decryptKey(ActionEvent event){
skey = RSADecryption(data);

    }

   public void generatePublicPrivateKeys (){
       try {
           KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
           kpg.initialize(2048);
           KeyPair kp = kpg.generateKeyPair();
           Key pub = kp.getPublic();
           Key pvt = kp.getPrivate();
           FileOutputStream outputStream = new FileOutputStream("privatekey.pvt");
           outputStream.write(pvt.getEncoded());
           outputStream.close();
           FileOutputStream outputStream2 = new FileOutputStream("publickey.pub");
           outputStream2.write(pub.getEncoded());
           outputStream2.close();

       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (FileNotFoundException e) {
           e.printStackTrace();
       } catch (IOException e) {
           e.printStackTrace();
       }


   }

   public byte[] RSAEncryption (SecretKey skey){
       Path path = Paths.get("publicKey.pub");
       byte[] bytes = new byte[0];
       try {
           bytes = Files.readAllBytes(path);
       } catch (IOException e) {
           e.printStackTrace();
       }

       /* Generate public key. */
       X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
       KeyFactory kf = null;
       PublicKey pub = null;
       try {
           kf = KeyFactory.getInstance("RSA");
           pub = kf.generatePublic(ks);
       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (InvalidKeySpecException e) {
           e.printStackTrace();
       }
       Cipher cipher = null;
       byte[] key = null;

       try
       {
           cipher = Cipher.getInstance("RSA");
           // contact.getPublicKey returns a public key of type Key
           cipher.init(Cipher.ENCRYPT_MODE, pub );
           // skey is the SecretKey used to encrypt the AES data
           key = cipher.doFinal(skey.getEncoded());
       }
       catch(Exception e )
       {
           System.out.println ( "exception encoding key: " + e.getMessage() );
           e.printStackTrace();
       }
       keyText.setText(byteToHexa(key));
       return key;

   }

    private SecretKey RSADecryption (byte[] data )
    {
        SecretKeySpec skey;
        PrivateKey priv= null;
        Cipher cipher;
        Path path = Paths.get("privateKey.pvt");
        byte[] privbytes = new byte[0];
        byte[] sbytes=null;
        try {
            privbytes = Files.readAllBytes(path);
          System.out.println(byteToHexa(privbytes));
        } catch (IOException e) {
            e.printStackTrace();
        }

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privbytes);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            priv = kf.generatePrivate(ks);
            System.out.println("priv key "+byteToHexa(priv.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        try
        {

            cipher = Cipher.getInstance("RSA");
            cipher.init(DECRYPT_MODE, priv );
           // cipher.init(Cipher.PRIVATE_KEY, priv );

             sbytes = cipher.doFinal(data);
            System.out.println("data "+ byteToHexa(data));
            System.out.println("b "+ byteToHexa(sbytes));
            keyText1.setText(byteToHexa(sbytes));
           skey = new SecretKeySpec(sbytes, "AES");


        }
        catch(Exception e)
        {
            System.out.println ( "exception decrypting the aes key: " + e.getMessage() );
            e.printStackTrace();
            return null;
        }

        return skey;
    }

}
