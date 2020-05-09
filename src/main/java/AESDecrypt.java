import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class AESDecrypt {
    private static final String characterEncoding = "UTF-8";
    private static final String cipherTransformation = "AES/CBC/PKCS5Padding";
    private static final String aesEncryptionAlgorithm = "AES";

    public static byte[] decryptBase64EncodedWithManagedIV(String encryptedText, String key) throws Exception {
        byte[] cipherText = Base64.decodeBase64(encryptedText.getBytes());
        byte[] keyBytes = Base64.decodeBase64(key.getBytes());
        return decryptWithManagedIV(cipherText, keyBytes);
    }

    public static byte[] decryptWithManagedIV(byte[] cipherText, byte[] key) throws Exception {
        byte[] initialVector = Arrays.copyOfRange(cipherText,0,16);                     //first 16 bytes of encrypted file is initialVector
        byte[] trimmedCipherText = Arrays.copyOfRange(cipherText,16,cipherText.length);     //we have to remove first 16 bytes and use the rest

        // with encrypted data, key and extracted initial vector we can proceed with file decryption
        return decrypt(trimmedCipherText, key, initialVector);
    }

    public static byte[] decrypt(byte[] cipherText, byte[] key, byte[] initialVector) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpecy = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpecy, ivParameterSpec);
        cipherText = cipher.doFinal(cipherText);
        return cipherText;
    }

    public static void main(String args[]) throws Exception {
        Options options = new Options();

        Option inputFile = new Option("i", "inputFile", true, "input encrypted file path");
        inputFile.setRequired(true);
        options.addOption(inputFile);

        Option inputKey = new Option("k", "inputKey", true, "input key file path");
        inputKey.setRequired(true);
        options.addOption(inputKey);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            formatter.printHelp("AESDecrypt", options);
            System.exit(1);
            return;
        }

        String inputFilePath = cmd.getOptionValue("inputFile").replace("\\", "/");
        String outputFilePath = cmd.getOptionValue("inputKey").replace("\\", "/");

        String fileName = null;
        String extension = null;
        if(inputFilePath.contains("/")) {
            String[] afterSplit = inputFilePath.split("/");
            String[] fileWithExtension = afterSplit[afterSplit.length - 1].split("\\.");
            fileName = fileWithExtension[0];
            extension = fileWithExtension.length > 1 ? '.' + fileWithExtension[1] : "";
        } else {
            String[] fileWithExtension = inputFilePath.split("\\.");
            fileName = fileWithExtension[0];
            extension = fileWithExtension.length > 1 ? '.' + fileWithExtension[1] : "";
        }
        byte[] encryptedData = null;
        byte[] aesKey = null;
        try {
            encryptedData = Files.readAllBytes(Paths.get(inputFilePath));    //first read data from encrypted file
        } catch (Exception ex) {
            System.out.println("Error loading encrypted file!");
            System.exit(1);
        }
        try {
            aesKey = Files.readAllBytes(Paths.get(outputFilePath));          //next read base64-coded encryption key
        } catch (Exception ex) {
            System.out.println("Error loading key file!");
            System.exit(1);
        }

        String data = Base64.encodeBase64String(encryptedData);                 //base64 encode our encrypted data and save to string
        String key = new String(aesKey, StandardCharsets.US_ASCII);             //cast the key to string

        byte[] clearText = decryptBase64EncodedWithManagedIV(data, key);        //run decryption

        String directory = inputFilePath.split(fileName).length > 1 ? inputFilePath.split(fileName)[0] : "";
        File file = new File(directory + fileName + "_decrypted" + extension);
        FileWriter fr = null;
        try {
            fr = new FileWriter(file);
            fr.write(new String(clearText, characterEncoding));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                fr.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}