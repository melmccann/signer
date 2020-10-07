# Reading a writing from files

There are two functions that read bytes from a file in the Cli. 

Firstly:
```java 
private byte[] readBytesFromFile(File fileLocation){
```
This reads all the bytes directly from the file. It doesn't trim or modify contents at all.  


Secondly:
```java
private byte[] readTrimmedBytesFromFile(File fileLocation){
```
This reads the contents of the file and removes leading or trailing whitespace from the String. 
An example of what trim() does is as follows:

```java
        String string = "\n\t testing the trim function \n\r\n \t";
        System.out.println("'"+string+"'");
        System.out.println("'"+string.trim()+"'");
```
Which outputs:
```java
'
	 testing the trim function 

 	'
'testing the trim function'
```


# Sha256 Input
Note that for the Sha256 function the result MAY be completely different depending on which method above you use to read from the file. 
They might also result in the same hash digest if there are no whitespace characters at the start and/or end of the file. 
<!-- Side note
If you want to remove the line ending from a file in vi you can do the following:
```bash 
:set noendofline binary
```
-->

If you want to verify the hash with another tool on linux you can do any of the following:

```bash
cat data.json | openssl dgst -sha256
```

```bash
cat data.json | shasum -a 256
```
Results are returned in hexadecimal format. 