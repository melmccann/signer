# Simple Signing Tool - Signer


## Introduction
This is a basic tool that allows one to:
* Create a sha256 hash from a file
* Verify a sha256 hash from a file
* Generate an Ed25519 key pair
* Create an Ed25519 digital signature
* Verify an Ed25519 digital signature

This was created for a very specific purpose but might be useful for others. 

## Build
You need to have Git, Java and Maven installed to build this project.
* https://git-scm.com/downloads
* https://www.oracle.com/ie/java/technologies/javase/javase-jdk8-downloads.html
* http://maven.apache.org/download.cgi 

```bash 
git clone https://github.com/melmccann/signer.git
cd signer
mvn clean package
```
The resulting jar file that you need to run this is located at `target/signer-jar-with-dependencies.jar`.

## Help

```bash
usage: java -jar target/signer-jar-with-dependencies.jar
 -data,--dataFile <dataFile>                File to be signed
 -encIn,--encodingIn <encodingIn>           The encoding of the file(s)
                                            that you want to read from.
                                            Default is RAW. Possible
                                            values are :
                                            RAW,HEX,BASE58,BASE64
 -encOut,--encodingOut <encodingOut>        The encoding of the file that
                                            you want to write from.
                                            Default is RAW. Possible
                                            values are :
                                            RAW,HEX,BASE58,BASE64
 -h,--help                                  Print this message
 -ha,--hash                                 Get the sha256 hash of a file
 -hf,--hashFile <hashFile>                  File that stores the sha256
                                            hash.
 -k,--keygen                                Generate public and private
                                            Ed25519 keys
 -priv,--privateKey <privateKeyFile>        Filename private key. Default
                                            is ./ed25519key.priv
 -pub,--publicKey <publicKeyFile>           Filename for public key.
                                            Default is ./ed25519key.pub
 -s,--sign                                  Sign a file
 -sigfile,--signatureFile <signatureFile>   File for storing the digital
                                            signature.
 -t,--trim                                  When reading from a file, read
                                            the content without leading
                                            and trailing whitespace.
 -vh,--verifyHash                           Verify a Sha256 Hash
 -vs,--verifySignature                      Verify a Ed25519 digital
                                            signature.

Usage Scenarios:

--keygen
Generate a public and private key pair and store in the default files. Public Key = ./ed25519key.pub and Private key = ./ed25519key.priv 

--keygen --publicKey <publicKeyFile> --privateKey <privateKeyFile>
Generate a public and private key pair and store in the specified files. 

--sign --privateKey <privateKeyFile> --hashFile <hashFile> --signatureFile <signatureFile>
Creates an Ed25519 digital signature of hashFile and writes to signatureFile

--hash --dataFile <datafile> --hashFile <hashFile>
Gets the Sha256 hash of the datafile and writes it to hashFile.

--verifySignature --signatureFile <signatureFile> --publicKey <publicKeyFile> --hashFile <hashFile> 
Reverses the signing process using the signature and the public key and then compares the result with the hash.

--verifyHash --dataFile <datafile> --hashFile <hashFile> 
Gets the Sha256 hash of the dataFile and compares with the hash in hashFile



```

Note that you can also specify the encoding for the input and output files. 
Available encodings are RAW,HEX,BASE58,BASE64.
RAW just reads or writes the exact bytes from/to the file. 

Also note that for the data file this option is not available, it is read as is. You can use `--trim` to read the contents of a file without including the leading or trailing whitespace.

E.g. Create keys in HEX format using
```bash
java -jar signer-jar-with-dependencies.jar --keygen --publicKey public.key --privateKey private.key --encodingOut HEX
```

## Full example
If you download the built version from GitHub the jar file name might be slightly different, e.g. `signer-0.0.1-jar-with-dependencies.jar`

```bash
# Generate the keys
$ java -jar signer-jar-with-dependencies.jar --keygen --publicKey public.key --privateKey private.key --encodingOut HEX

# Check contents of files
$ cat public.key 
4b595dc6410a9be1fe760e05156707f14981f1cee16b5ba0f84006a4b6c57377 
$ cat private.key 
445db8fd1901d3135b0e8c4c01187539ffc1c76b4a4e8b0bcbb75d1cde5cd693m

# Hash some data 
$ wget https://github.com/melmccann/signer/blob/aa8671cb3cc7aaac19c6a88c3326ffafb22dbcce/src/main/resources/data.json

# Get the Sha256 hash of the data and save in file
$ java -jar signer-jar-with-dependencies.jar --hash --dataFile data.json --hashFile data_hash.txt  --encodingIn HEX --encodingOut HEX

$ cat data_hash.txt 
16957169319852e87cf1959d62a2fac3fed60ef6638eb7daa37739be7d3fb115

# verify the hash
$ java -jar signer-jar-with-dependencies.jar --verifyHash --dataFile data.json --hashFile data_hash.txt  --encodingIn HEX
...
PASS: hash is verified!!

# Sign the hash using the private key

$ java -jar signer-jar-with-dependencies.jar --sign --privateKey private.key --hashFile data_hash.txt --signatureFile signature.txt --encodingIn HEX --encodingOut HEX
$ cat signature.txt 
3f4cc30262be115a83bd286086c5ee74fd0e9bf6f09d9869ba4c669500450c0b709f06f7fa66fbf9a348fe5cb3fcf150e5535a6e9053fa3b4f73eda420a8fa07

# Verify the signature
$ java -jar signer-jar-with-dependencies.jar --verifySignature --publicKey public.key --hashFile data_hash.txt --signatureFile signature.txt --encodingIn HEX 
...
PASS: digital signature is verified!!

```


