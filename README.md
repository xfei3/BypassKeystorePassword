# Description
Did some research about keystore and want to share my findings.
1. Keystore password is not important and can be easily bypassed which a lot of ppl don`t know. JDK code just read the hash of keystore password and compare with hash of user input.
According to Oracle: For the JCEKS keystore, the password is just used for integrity checking. 
We can call load(stream, null) to bypass the integrity check and then call getKey(alias, keypass).
2. though it is easy to get hash of keystore password, such hash went though several round of re-hash and possibly other process. Cracking it is highly unlikely.
3. there is already research about how to get real hash of password of JKS keystore then crack the hash. However seems it is impossible to get real hash of JCEKS keystore password.
