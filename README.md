# Description
Did some research about keystore and want to share my findings.
1. Keystore password is not important and can be easily bypassed which a lot of ppl don`t know. JDK code just read the hash of keystore password from keystore and compare with hash of user input.
According to Oracle: "For the JCEKS keystore, the password is just used for integrity checking, not for security."
We can call load(stream, null) to bypass the integrity check and then call getKey(alias, keypass). So if you think a complex keystore password could protect you and an easy key password is fine, then you are wrong!
2. though it is easy to get final hash of keystore password, such hash went though several round of re-hashing and possibly other process. Cracking it is highly unlikely.
3. there is already research about how to get real hash of password of JKS keystore then crack the hash. However seems it is impossible to get real hash of JCEKS keystore password.

#POC code
java version "1.8.0_171"


I wrote some code to read JCEKS/JKS keystore and extract final hash of keystore password and read key without knowing keystore password(You still need to know the key password).
You can compile the code and run command like: 


java -jar jarName.jar path/to/jceks JCEKS {keypassword} {keyalias}


It will print final hash and try to encrypt and decrypt test string using the key if the key password is correct.
