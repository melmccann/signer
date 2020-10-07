package com.melmccann;

import org.apache.commons.cli.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileExistsException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.EnumUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Tool for performing sha256 hashing and Ed25519 signing
 */
public class Cli {
    private String commandName = "java -jar signer.jar";
    private Options options;
    private String publicKeyLocation = "./ed25519key.pub";
    private String privateKeyLocation = "./ed25519key.priv";
    private boolean trim = false;

    public enum encoding {
        RAW, HEX, BASE58, BASE64
    }

    private encoding inputEncoding = encoding.RAW;
    private encoding outputEncoding = encoding.RAW;

    public static void main(String[] args) {
        Cli cli = new Cli();
        try {
            cli.execute(args);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void execute(String[] args) throws Exception {

        //Options without arguments
        Option help = new Option("h", "help", false, "Print this message");
        Option version = new Option("v", "version", false, "Print the version information and exit");
        Option debug = new Option("d", "debug", false, "Print debugging information");
        Option keygen = new Option("k", "keygen", false, "Generate public and private Ed25519 keys");
        Option sign = new Option("s", "sign", false, "Sign a file");
        Option hash = new Option("ha", "hash", false, "Get the sha256 hash of a file");
        Option verifySignature = new Option("vs", "verifySignature", false, "Verify a Ed25519 digital signature.");
        Option verifyHash = new Option("vh", "verifyHash", false, "Verify a Sha256 Hash");
        Option trim = new Option("t", "trim", false, "When reading from a file, read the content without leading and trailing whitespace.");

        //Options with arguments
        Option publicKey = new Option("pub", "publicKey", true, "Filename for public key. Default is " + this.publicKeyLocation);
        publicKey.setArgName("publicKeyFile");
        publicKey.setRequired(false);

        Option privateKey = new Option("priv", "privateKey", true, "Filename private key. Default is " + this.privateKeyLocation);
        privateKey.setArgName("privateKeyFile");
        privateKey.setRequired(false);

        Option dataFile = new Option("data", "dataFile", true, "File to be signed");
        dataFile.setArgName("dataFile");
        dataFile.setRequired(false);

        Option hashFile = new Option("hf", "hashFile", true, "File that stores the sha256 hash.");
        hashFile.setArgName("hashFile");
        hashFile.setRequired(false);

        Option signatureFile = new Option("sigfile", "signatureFile", true, "File for storing the digital signature.");
        signatureFile.setArgName("signatureFile");
        signatureFile.setRequired(false);

        String encodingValues = Arrays.stream(encoding.values())
                .map(Enum::toString)
                .collect(Collectors.joining(","));

        Option encodingIn = new Option("encIn", "encodingIn", true, "The encoding of the file(s) that you want to read from. Default is RAW. Possible values are : " + encodingValues);
        encodingIn.setArgName("encodingIn");
        encodingIn.setRequired(false);

        Option encodingOut = new Option("encOut", "encodingOut", true, "The encoding of the file that you want to write from. Default is RAW. Possible values are : " + encodingValues);
        encodingOut.setArgName("encodingOut");
        encodingOut.setRequired(false);


        options = new Options();
        options.addOption(help);
        options.addOption(publicKey);
        options.addOption(privateKey);
        options.addOption(keygen);
        options.addOption(sign);
        options.addOption(hash);
        options.addOption(dataFile);
        options.addOption(hashFile);
        options.addOption(verifySignature);
        options.addOption(verifyHash);
        options.addOption(signatureFile);
        options.addOption(trim);
        options.addOption(encodingIn);
        options.addOption(encodingOut);

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        String commands[] = cmd.getArgs();
        this.processCommands(commands, cmd);


    }

    private void processCommands(String[] commands, CommandLine cmd) {
        if (cmd.hasOption("help")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(this.commandName, this.options);
            System.out.println(this.usageExamples());
            System.exit(0);
        }
        if (this.hasCommandOverlap(cmd)) {
            System.exit(0);
        }
        if (cmd.hasOption("trim")) {
            this.trim = true;
        }
        if (cmd.hasOption("encodingIn")) {
            if (!EnumUtils.isValidEnum(encoding.class, cmd.getOptionValue("encodingIn"))) {
                System.out.println("encodingIn must be one of the following values.Default is RAW. All available options are: " + this.getEncodingValues());
                System.exit(0);
            } else {
                this.inputEncoding = this.parseEncoding(cmd.getOptionValue("encodingIn"));
            }
        }
        if (cmd.hasOption("encodingOut")) {
            if (!EnumUtils.isValidEnum(encoding.class, cmd.getOptionValue("encodingOut"))) {
                System.out.println("encodingOut must be one of the following values.Default is RAW. All available options are: " + this.getEncodingValues());
                System.exit(0);
            } else {
                this.outputEncoding = this.parseEncoding(cmd.getOptionValue("encodingOut"));
            }
        }

        if (cmd.hasOption("keygen")) {
            System.out.println("Generating new key pair...");
            try {
                this.keygen();
            } catch (Exception ex) {
                System.out.println("There was an error when trying to generate the key pair.");
            }
        } else if (cmd.hasOption("hash")) {
            if (!cmd.hasOption("dataFile") || !cmd.hasOption("hashFile")) {
                System.out.println("you must specify both the '--dataFile' and the '--hashFile'");
                System.exit(0);
            } else {
                this.hash(cmd.getOptionValue("dataFile"), cmd.getOptionValue("hashFile"));
            }
        } else if (cmd.hasOption("sign")) {
            if (!cmd.hasOption("privateKey") || !cmd.hasOption("hashFile") || !cmd.hasOption("signatureFile")) {
                System.out.println("you must specify all of the following: '--privateKey' and '--signatureFile'");
                System.exit(0);
            } else {
                try {
                    this.sign(cmd.getOptionValue("privateKey"), cmd.getOptionValue("hashFile"), cmd.getOptionValue("signatureFile"));
                }catch(DecoderException dex){
                    System.out.println("Could not decode file: ");
                    System.exit(0);
                }
            }
        } else if (cmd.hasOption("verifyHash")) {
            if (!cmd.hasOption("dataFile") || !cmd.hasOption("hashFile")) {
                System.out.println("you must specify both the '--dataFile' and the '--hashFile'");
                System.exit(0);
            } else {
                boolean verified = this.verifyHash(cmd.getOptionValue("dataFile"), cmd.getOptionValue("hashFile"));
                if (verified) {
                    System.out.println("PASS: hash is verified!!");
                } else {
                    System.out.println("FAILED: hash verification failed!!");
                }
            }
        } else if (cmd.hasOption("verifySignature")) {
            if (!cmd.hasOption("publicKey") || !cmd.hasOption("hashFile") || !cmd.hasOption("signatureFile")) {
                System.out.println("you must specify all of the following: '--privateKey' and '--signatureFile'");
                System.exit(0);
            } else {
                try {
                    boolean verified = this.verifySignature(cmd.getOptionValue("publicKey"), cmd.getOptionValue("hashFile"), cmd.getOptionValue("signatureFile"));
                    if (verified) {
                        System.out.println("PASS: digital signature is verified!!");
                    } else {
                        System.out.println("FAILED: digital signature verification failed!!");
                    }
                }catch(DecoderException dex){
                    System.out.println("Could not decode file: ");
                    System.exit(0);
                }
            }
        }

    }

    private String usageExamples() {
        StringBuffer buf = new StringBuffer();
        buf.append("\nUsage Scenarios:\n\n");
        //create keys
        buf.append("--keygen\n");
        buf.append("Generate a public and private key pair and store in the default files. Public Key = " + this.publicKeyLocation + " and Private key = " + this.privateKeyLocation + " \n\n");
        buf.append("--keygen --publicKey <publicKeyFile> --privateKey <privateKeyFile>\n");
        buf.append("Generate a public and private key pair and store in the specified files. \n\n");

        //sign a file
        buf.append("--sign --privateKey <privateKeyFile> --hashFile <hashFile> --signatureFile <signatureFile>\n");
        buf.append("Creates an Ed25519 digital signature of hashFile and writes to signatureFile\n\n");

        buf.append("--hash --dataFile <datafile> --hashFile <hashFile>\n");
        buf.append("Gets the Sha256 hash of the datafile and writes it to hashFile.\n\n");

        buf.append("--verifySignature --signatureFile <signatureFile> --publicKey <publicKeyFile> --hashFile <hashFile> \n");
        buf.append("Reverses the signing process using the signature and the public key and then compares the result with the hash.\n\n");

        buf.append("--verifyHash --dataFile <datafile> --hashFile <hashFile> \n");
        buf.append("Gets the Sha256 hash of the dataFile and compares with the hash in hashFile");

        return buf.toString();

    }

    private boolean hasCommandOverlap(CommandLine cmd) {
        int overlapCount = 0;

        if (cmd.hasOption("k")) {
            overlapCount++;
        }
        if (cmd.hasOption("s")) {
            overlapCount++;
        }
        if (cmd.hasOption("vh")) {
            overlapCount++;
        }
        if (cmd.hasOption("vs")) {
            overlapCount++;
        }
        if (cmd.hasOption("ha")) {
            overlapCount++;
        }
        if (overlapCount == 0) {
            try {
                System.out.println("You must use one of the follow:" +
                        "" + cmd.getParsedOptionValue("k"));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            return true;
        } else if (overlapCount > 1) {
            System.out.println("You cannot use more than one of the following:\n" +
                    "" + this.prettyPrintOption("k") + "\n" +
                    "" + this.prettyPrintOption("s") + "\n" +
                    "" + this.prettyPrintOption("vs") + "\n" +
                    "" + this.prettyPrintOption("ha") + "\n" +
                    "" + this.prettyPrintOption("vh") + "\n");
            return true;
        }
        return false;
    }

    private String prettyPrintOption(String opt) {
        Option option = options.getOption(opt);
        String prefix = "-" + option.getOpt() + ", --" + option.getLongOpt();
        int tabsCount = 10 - Math.round(prefix.length() / 4);
        StringBuffer tabs = new StringBuffer();
        for (int i = 0; i <= tabsCount; i++) {
            tabs.append("\t");
        }
        String line = prefix + tabs.toString() + option.getDescription();
        return line;
    }

    public boolean keygen() throws FileExistsException, IOException {
        File publicKey = new File(this.publicKeyLocation);
        File privateKey = new File(this.privateKeyLocation);
        if (publicKey.exists()) {
            throw new FileExistsException("The public key already exists: " + publicKey.getAbsolutePath());
        } else if (privateKey.exists()) {
            throw new FileExistsException("The private key already exists: " + privateKey.getAbsolutePath());
        }
        byte[] privateKeyBytes = new byte[Ed25519.SECRET_KEY_SIZE];
        byte[] publicKeyBytes = new byte[Ed25519.PUBLIC_KEY_SIZE];
        SecureRandom RANDOM = new SecureRandom();
        RANDOM.nextBytes(privateKeyBytes);
        Ed25519.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        System.out.println("private key in Hex = " + Hex.encodeHexString(privateKeyBytes));
        System.out.println("Writing private key bytes to file: " + privateKey.getAbsolutePath());
        System.out.println("public key in Hex= " + Hex.encodeHexString(publicKeyBytes));
        System.out.println("Writing public key bytes to file: " + publicKey.getAbsolutePath());
        this.writeToFile(publicKey, publicKeyBytes);
        this.writeToFile(privateKey, privateKeyBytes);
        return true;
    }

    public byte[] hash(String dataFileLocation, String hashFileLocation) {
        File dataFile = new File(dataFileLocation);
        byte[] digest = new byte[0];
        if (!dataFile.exists()) {
            System.out.println("The dataFile does not exist: " + dataFile.getAbsolutePath());
            System.exit(0);
        }
        File hashFile = new File(hashFileLocation);
        if (hashFile.exists()) {
            System.out.println("The hashFile already exists: " + hashFile.getAbsolutePath());
            System.exit(0);
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            if(this.trim) {
                sha.update(this.readTrimmedBytesFromFile(dataFile));
            }else{
                sha.update(this.readBytesFromFile(dataFile));
            }
            digest = sha.digest();
            //System.out.println(new String(digest));
            System.out.println(Hex.encodeHexString(digest));
            try {
                this.writeToFile(hashFile, digest);
                System.out.println("Sha256 hash bytes written to file: " + hashFile.getAbsolutePath());
            } catch (IOException ioex) {
                System.out.println("There was a problem writing the hash to the file: " + hashFile.getAbsolutePath());
            }
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Could not create the sha256 hash of file: " + dataFileLocation);
            System.exit(0);
        }
        return digest;
    }

    public boolean verifyHash(String dataFileLocation, String hashFileLocation) {
        File dataFile = new File(dataFileLocation);
        File hashFile = new File(hashFileLocation);
        byte[] digest = new byte[0];
        if (!dataFile.exists()) {
            System.out.println("The dataFile does not exist: " + dataFile.getAbsolutePath());
            System.exit(0);
        }

        if (!hashFile.exists()) {
            System.out.println("The hashFile does not exist: " + hashFile.getAbsolutePath());
            System.exit(0);
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            if(this.trim) {
                sha.update(this.readTrimmedBytesFromFile(dataFile));
            }else{
                sha.update(this.readBytesFromFile(dataFile));
            }
            digest = sha.digest();
            byte hash[] = this.readEncodedFile(hashFile);
            if (Arrays.equals(digest, hash)) {
                return true;
            }
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Could not create the sha256 hash of file: " + dataFileLocation);
            System.exit(0);
        }catch(DecoderException dex){
            System.out.println("Could not decode file, dataFile or hashFile");
            System.exit(0);
        }
        return false;
    }

    public void setInputEncoding(String encodingValue) {
        this.inputEncoding = parseEncoding(encodingValue);
    }

    public void setOutputEncoding(String encodingValue) {
        this.outputEncoding = this.parseEncoding(encodingValue);
    }

    public encoding parseEncoding(String encodingValue) {
        encoding updateEncoding = encoding.valueOf(encodingValue);
        switch (updateEncoding) {
            case HEX:
                return encoding.HEX;
            case BASE58:
                return encoding.BASE58;
            case BASE64:
                return encoding.BASE64;
            default:
                return encoding.RAW;
        }
    }

    /**
     * Creates an Ed25519 signature of hashFile using the private key in privateKeyFile and writes it to signatureFile
     *
     * @param privateKeyFileLocation
     * @param hashFileLocation
     * @param signatureFileLocation
     */
    public byte[] sign(String privateKeyFileLocation, String hashFileLocation, String signatureFileLocation) throws DecoderException{
        File privateKeyFile = new File(privateKeyFileLocation);
        File hashFile = new File(hashFileLocation);
        File signatureFile = new File(signatureFileLocation);
        if (!privateKeyFile.exists()) {
            System.out.println("The private key file doesn't exist: " + privateKeyFile.getAbsolutePath());
            System.exit(0);
        }
        if (!hashFile.exists()) {
            System.out.println("The hash file doesn't exist: " + hashFile.getAbsolutePath());
            System.exit(0);
        }
        if (signatureFile.exists()) {
            System.out.println("Signature file already exists: " + signatureFile.getAbsolutePath());
            System.exit(0);
        }

        byte[] signature = new byte[Ed25519.SIGNATURE_SIZE];
        byte privateKeyBytes[] = this.readEncodedFile(privateKeyFile);
        System.out.println("private key: " + Hex.encodeHexString(privateKeyBytes));
        byte msg[] = this.readEncodedFile(hashFile);
        System.out.println("hash: " + Hex.encodeHexString(msg));
        Ed25519.sign(privateKeyBytes, 0, msg, 0, msg.length, signature, 0);
        String signatureHex = Hex.encodeHexString(signature);
        System.out.println("Signature as hex: " + signatureHex);
        try {
            this.writeToFile(signatureFile, signature);
            System.out.println("Ed25519 digital signature bytes written to signature file: " + signatureFile.getAbsolutePath());
        } catch (IOException ioex) {
            System.out.println("There was a problem writing the signature to the file: " + signatureFile.getAbsolutePath());
        }
        return signature;
    }

    public boolean verifySignature(String publicKeyFileLocation, String hashFileLocation, String signatureFileLocation) throws DecoderException{
        File publicKeyFile = new File(publicKeyFileLocation);
        File hashFile = new File(hashFileLocation);
        File signatureFile = new File(signatureFileLocation);
        if (!publicKeyFile.exists()) {
            System.out.println("The public key file doesn't exist: " + publicKeyFile.getAbsolutePath());
            System.exit(0);
        }
        if (!hashFile.exists()) {
            System.out.println("The hash file doesn't exist: " + hashFile.getAbsolutePath());
            System.exit(0);
        }
        if (!signatureFile.exists()) {
            System.out.println("Signature file doesn't exists: " + signatureFile.getAbsolutePath());
            System.exit(0);
        }

        byte[] signature = new byte[Ed25519.SIGNATURE_SIZE];
        byte publicKeyBytes[] = this.readEncodedFile(publicKeyFile);
        byte signatureFileBytes[] = this.readEncodedFile(signatureFile);
        System.out.println("public key: " + Hex.encodeHexString(publicKeyBytes));
        byte msg[] = this.readEncodedFile(hashFile);
        System.out.println("hash: " + Hex.encodeHexString(msg));
//        boolean shouldVerify = Ed25519.verify(sig1, 0, pk, 0, m, 0, mLen);
        return Ed25519.verify(signatureFileBytes, 0, publicKeyBytes, 0, msg, 0, msg.length);
    }

    /**
     * Read all the bytes from a file. This includes whitespace characters at the end and start of a file.
     *
     * @param fileLocation
     * @return
     */
    public byte[] readBytesFromFile(File fileLocation) {
        System.out.println("Getting raw data from file");
        byte data[] = new byte[0];
        try {
            data = FileUtils.readFileToByteArray(fileLocation);
        } catch (IOException ioex) {
            System.out.println("Could not get data from file: " + fileLocation.getAbsolutePath());
            System.exit(0);
        }
        return data;
    }

    /**
     * Read the contents of a file and remove the leading and trailing whitespace characters using String.trim()
     *
     * @param fileLocation
     * @return
     */
    public byte[] readTrimmedBytesFromFile(File fileLocation) {
        System.out.println("Getting trimmed data from file");
        String data = new String();
        try {
            data = FileUtils.readFileToString(fileLocation, "UTF-8").trim();
        } catch (IOException ioex) {
            System.out.println("Could not get data from file: " + fileLocation.getAbsolutePath());
        }
        return data.getBytes();
    }

    /**
     * Default is hex
     *
     * @param fileLocation
     * @return
     */
    public byte[] readEncodedFile(File fileLocation) throws DecoderException {
        byte data[] = this.readTrimmedBytesFromFile(fileLocation);
        switch (this.inputEncoding) {
            case HEX:
                System.out.println("Reading Hex/Base16 string from file: " + fileLocation.getAbsolutePath());
                return Hex.decodeHex(new String(data));
            case BASE58:
                System.out.println("Reading Base58 string from file: " + fileLocation.getAbsolutePath());
                return Base58.decode(new String(data));
            case BASE64:
                System.out.println("Reading Base64 string from file: " + fileLocation.getAbsolutePath());
                return Base64.getDecoder().decode(data);
            default:
                System.out.println("Reading raw bytes from file: " + fileLocation.getAbsolutePath());
                if (this.trim) {
                    data = this.readTrimmedBytesFromFile(fileLocation);
                } else {
                    data = this.readBytesFromFile(fileLocation);
                }
                return data;
        }
    }

    public boolean writeToFile(File fileLocation, byte[] data) throws IOException {
        switch (this.outputEncoding) {
            case HEX:
                String outputHex = Hex.encodeHexString(data);
                System.out.println("Hex/Base16 data: " + outputHex);
                FileUtils.writeStringToFile(fileLocation, outputHex, "UTF-8");
                System.out.println("Data written to file as HEX/Base16: " + fileLocation.getAbsolutePath());
                return true;
            case BASE58:
                String outputBase58 = Base58.encode(data);
                System.out.println("Base58 data: " + outputBase58);
                FileUtils.writeStringToFile(fileLocation, outputBase58, "UTF-8");
                System.out.println("Data written to file as Base58: " + fileLocation.getAbsolutePath());
                return true;
            case BASE64:
                String outputBase64 = Base64.getEncoder().encodeToString(data);
                System.out.println("Base64 data: " + outputBase64);
                FileUtils.writeStringToFile(fileLocation, outputBase64, "UTF-8");
                System.out.println("Data written to file as Base64: " + fileLocation.getAbsolutePath());
                return true;
            default:
               // System.out.println("Raw bytes: " + (new String(data)));
                FileUtils.writeByteArrayToFile(fileLocation, data);
                System.out.println("Raw data bytes written to file: " + fileLocation.getAbsolutePath());
                return true;
        }
    }

    public String getEncodingValues() {
        String encodingValues = Arrays.stream(encoding.values())
                .map(Enum::toString)
                .collect(Collectors.joining(","));
        return encodingValues;
    }

    public encoding getInputEncoding() {
        return inputEncoding;
    }

    public void setInputEncoding(encoding inputEncoding) {
        this.inputEncoding = inputEncoding;
    }

    public encoding getOutputEncoding() {
        return outputEncoding;
    }

    public void setOutputEncoding(encoding outputEncoding) {
        this.outputEncoding = outputEncoding;
    }

    public String getPublicKeyLocation() {
        return publicKeyLocation;
    }

    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
    }

    public String getPrivateKeyLocation() {
        return privateKeyLocation;
    }

    public void setPrivateKeyLocation(String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation;
    }
}
