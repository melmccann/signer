package com.melmccann;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CliTest {
    File dataFile;
    File tempFiles[];
    File tempDir;
    Cli cli;
    ClassLoader classLoader;

    @Before
    public void setUp() throws Exception {
        this.cli = new Cli();
        tempFiles = new File[0];
        String resourceDataFile = "data.json";
        this.classLoader = getClass().getClassLoader();
        this.dataFile = new File(this.classLoader.getResource(resourceDataFile).getFile());
        System.out.println(this.dataFile.getAbsolutePath());
        String dir = this.dataFile.getParent();
        this.tempDir = new File(dir + "/temp");

        //set up test vector files as in https://tools.ietf.org/html/rfc8032


    }

    @After
    public void tearDown() throws Exception {
        this.cli = null;
        System.out.println(this.tempDir.getAbsolutePath());
        for (File tempFile : this.tempFiles
        ) {
            tempFile.delete();
        }

    }

    @Test
    public void execute() {
    }

    @Test
    public void keygen() {
        //generate keys
        File privateKeyFileLocation = new File(this.tempDir + "/temp_privatekey_hex.txt");
        File publicKeyFileLocation = new File(this.tempDir + "/temp_publickey_hex.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, privateKeyFileLocation);
        this.tempFiles = ArrayUtils.add(this.tempFiles, publicKeyFileLocation);
        cli.setPrivateKeyLocation(privateKeyFileLocation.getAbsolutePath());
        cli.setPublicKeyLocation(publicKeyFileLocation.getAbsolutePath());
        try {
            cli.keygen();
        }catch (Exception ex){
            assertTrue(false);
        }

        //create hash file
        File tempHashFile = new File(this.tempDir + "/temp_hashtest2.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, tempHashFile);
        byte newHashBytes[] = cli.hash(this.dataFile.getAbsolutePath(), tempHashFile.getAbsolutePath());

        //sign
        File tempsignatureFile = new File(this.tempDir + "/temp__signature2.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, tempsignatureFile);
        try {
            byte sig[] = this.cli.sign(privateKeyFileLocation.getAbsolutePath(), tempHashFile.getAbsolutePath(), tempsignatureFile.getAbsolutePath());
            // verify
            boolean verified = this.cli.verifySignature(publicKeyFileLocation.getAbsolutePath(), tempHashFile.getAbsolutePath(), tempsignatureFile.getAbsolutePath());
            System.out.println(verified);
            assertTrue(verified);
        }catch (DecoderException dex){
            assertTrue(false);
        }

    }


    @Test
    public void keygenHex() {
        this.cli.setInputEncoding("HEX");
        this.cli.setOutputEncoding("HEX");
        //generate keys
        File privateKeyFileLocation = new File(this.tempDir + "/temp_privatekey_hex.txt");
        File publicKeyFileLocation = new File(this.tempDir + "/temp_publickey_hex.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, privateKeyFileLocation);
        this.tempFiles = ArrayUtils.add(this.tempFiles, publicKeyFileLocation);
        cli.setPrivateKeyLocation(privateKeyFileLocation.getAbsolutePath());
        cli.setPublicKeyLocation(publicKeyFileLocation.getAbsolutePath());
        try {
            cli.keygen();
        }catch (Exception ex){
            ex.printStackTrace();
            assertTrue(false);
        }

        //create hash file
        File tempHashFile = new File(this.tempDir + "/temp_hashtest2.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, tempHashFile);
        byte newHashBytes[] = cli.hash(this.dataFile.getAbsolutePath(), tempHashFile.getAbsolutePath());

        //sign
        File tempSignatureFile = new File(this.tempDir + "/temp__signature2.txt");
        this.tempFiles = ArrayUtils.add(this.tempFiles, tempSignatureFile);
        try {
            byte sig[] = this.cli.sign(privateKeyFileLocation.getAbsolutePath(), tempHashFile.getAbsolutePath(), tempSignatureFile.getAbsolutePath());
            // verify
            boolean verified = this.cli.verifySignature(publicKeyFileLocation.getAbsolutePath(), tempHashFile.getAbsolutePath(), tempSignatureFile.getAbsolutePath());
            System.out.println(verified);
            assertTrue(verified);
        }catch (DecoderException dex){
            assertTrue(false);
        }

    }

    @Test
    public void hash() {
        File hashFile = new File(this.classLoader.getResource("data_hash_hex.txt").getFile());

        String tempHashFileLocation = this.tempDir + "/temp_testvector_hashtest1.txt";
        File tempHashFile = new File(tempHashFileLocation);
        this.tempFiles = ArrayUtils.add(this.tempFiles, tempHashFile);
        try {
            String originalHashBase16 = FileUtils.readFileToString(hashFile, "UTF-8");
            System.out.println("original hash = " + originalHashBase16);
            byte newHashBytes[] = cli.hash(this.dataFile.getAbsolutePath(), tempHashFile.getAbsolutePath());
            String newHashBase16 = Hex.encodeHexString(newHashBytes);
            System.out.println("new hash = " + newHashBase16);
            assertEquals(originalHashBase16, newHashBase16);
        } catch (IOException ioex) {
            assertTrue(false);
        }
    }

    @Test
    public void verifyHash() {
        this.cli.setInputEncoding("HEX");
        File hashFile = new File(this.classLoader.getResource("data_hash_hex.txt").getFile());
        boolean verified = cli.verifyHash(this.dataFile.getAbsolutePath(), hashFile.getAbsolutePath());
        assertTrue(verified);
    }

    @Test
    public void setInputEncoding() {
        cli.setInputEncoding("BASE58");
        assertEquals(cli.getInputEncoding(), Cli.encoding.BASE58);
    }

    @Test
    public void setOutputEncoding() {
        cli.setOutputEncoding("BASE64");
        assertEquals(cli.getOutputEncoding(), Cli.encoding.BASE64);
    }

    @Test
    public void sign() {
        String indexes[] = {"1", "2", "3", "1024"};
        for (String index : indexes
        ) {
            this.cli.setInputEncoding("HEX");
            String privateKeyFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_privatekey_hex.txt").getPath();
            String hashFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_message_hex.txt").getPath();
            String signatureFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_signature_hex.txt").getPath();
            String tempsignatureFileLocation = this.tempDir + "/temp_testvector" + index + "_signature_hex.txt";
            this.tempFiles = ArrayUtils.add(this.tempFiles, new File(tempsignatureFileLocation));
            try {
                //String privateKeyFileLocation, String hashFileLocation, String signatureFileLocation
                byte sig[] = this.cli.sign(privateKeyFileLocation, hashFileLocation, tempsignatureFileLocation);

                assertTrue(Arrays.equals(sig, cli.readEncodedFile(new File(signatureFileLocation))));
            } catch (DecoderException dex) {
                assertTrue(false);
            }
        }
    }

    @Test
    public void verifySignature() {
        //test against some of the test vectors in https://tools.ietf.org/html/rfc8032#page-24
        String indexes[] = {"1", "2", "3", "1024"};
        for (String index : indexes
        ) {
            this.cli.setInputEncoding("HEX");
            String publicKeyFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_publickey_hex.txt").getPath();
            String hashFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_message_hex.txt").getPath();
            String signatureFileLocation = this.classLoader.getResource("testVectors/testvector" + index + "_signature_hex.txt").getPath();
            try {
                boolean verified = this.cli.verifySignature(publicKeyFileLocation, hashFileLocation, signatureFileLocation);
                System.out.println(verified);
                assertTrue(verified);
            } catch (DecoderException dex) {
                assertTrue(false);
            }
        }
    }
}