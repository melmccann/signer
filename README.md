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
usage: java -jar signer.jar
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
java -jar target/signer-jar-with-dependencies.jar --keygen --publicKey public.key --privateKey private.key --encodingOut HEX

```