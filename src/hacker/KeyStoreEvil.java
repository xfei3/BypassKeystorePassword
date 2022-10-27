package hacker;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreEvil extends KeyStore {
    private KeyStoreSpi keyStoreSpi;

    // Has this keystore been initialized (loaded)?
    private boolean initialized = false;

    /**
     * Creates a KeyStore object of the given type, and encapsulates the given
     * provider implementation (SPI object) in it.
     *
     * @param keyStoreSpi the provider implementation.
     * @param provider    the provider.
     * @param type        the keystore type.
     */
    protected KeyStoreEvil(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
        //JceKeyStore
    }

    public static KeyStore getInstance(String type)
            throws KeyStoreException {
        try {
            Class<Security> clazz = Security.class;
            Method method = clazz.getDeclaredMethod("getImpl", String.class,String.class,String.class);
            method.setAccessible(true);

            Object[] objs = (Object[]) method.invoke(null, type, "KeyStore", (String) null);
            //Object[] objs = Security.getImpl(type, "KeyStore", (String)null);
            return new KeyStoreEvil((KeyStoreSpi) objs[0], (Provider) objs[1], type);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return null;
    }




    public final void evil_load(InputStream stream, char[] storepass)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        JceKeyStoreEvil jceks = new JceKeyStoreEvil();
        jceks.engineLoad(stream, storepass);
//        initialized = true;
//        try {
//            jceks.stealKey("cert1","12345".toCharArray());
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
//        }
    }
    public final Key evil_load(InputStream stream, String keyAlias, char[] storepass, char[] keypass)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        JceKeyStoreEvil jceks = new JceKeyStoreEvil();
        jceks.engineLoad(stream, storepass);
        initialized = true;
        try {
            return jceks.stealKey(keyAlias,keypass);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

}
