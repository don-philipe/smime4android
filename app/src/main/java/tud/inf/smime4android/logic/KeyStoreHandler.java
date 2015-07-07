package tud.inf.smime4android.logic;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Created by don on 24.06.15.
 */
public class KeyStoreHandler {

    /**
     *
     * @param keystorefile
     * @param password for the keystore
     */
    public static void initKeyStore(File keystorefile, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS7", "BC");
            ks.load(null, null);
            ks.store(new FileOutputStream(keystorefile), password);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param keystorefile
     * @param ksPassword
     * @param alias key alias
     * @param certs certificate chain where certs[0] is the clients certificate, certs[1] ... certs[n] are intermediate certificates and certs[n+1] is the root certificate
     * @param privkey
     * @param keyPassword
     */
    public static void addCertificate(File keystorefile, char[] ksPassword, String alias, Certificate[] certs, PrivateKey privkey, char[] keyPassword) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS7", "BC");
            ks.load(new FileInputStream(keystorefile), ksPassword);
            ks.setKeyEntry(alias, privkey, keyPassword, certs);
            ks.store(new FileOutputStream(keystorefile), ksPassword);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param ksFile
     * @param ksPassword
     * @return null in case something went wrong while loading keystorefile
     * @throws
     */
    public static X509Certificate getCertificate(String ksFile, char[] ksPassword) throws NoSuchFieldException {
        try {
            KeyStore ks = getKeyStore(ksFile, ksPassword);
            if(ks != null) {
                String keyAlias = getKeyAlias(ks, ksPassword);
                return (X509Certificate) ks.getCertificate(keyAlias);
            }
            else
                throw new NoSuchFieldException("can't get keystore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param ksFile
     * @param ksPassword
     * @return
     * @throws NoSuchFieldException
     */
    public static PrivateKey getPrivKey(String ksFile, char[] ksPassword) throws NoSuchFieldException{
        try {
            KeyStore ks = getKeyStore(ksFile, ksPassword);
            if(ks != null) {
                String keyAlias = getKeyAlias(ks, ksPassword);
                return (PrivateKey) ks.getKey(keyAlias, null);
            }
            else
                throw new NoSuchFieldException("can't get keystore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param ksFile
     * @param ksPassword
     * @return can be null
     * @throws NoSuchFieldException
     */
    protected static KeyStore getKeyStore(String ksFile, char[] ksPassword) throws NoSuchFieldException {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS7", "BC");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        File keystorefile = new File(ksFile);
        if(keystorefile.exists()) {
            try {
                ks.load(new FileInputStream(keystorefile), ksPassword);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
        else
            throw new NoSuchFieldException("keystorefile doesn't exist");
        return ks;
    }

    /**
     *
     * @param ks
     * @param ksPassword
     * @return
     * @throws KeyStoreException
     */
    protected static String getKeyAlias(KeyStore ks, char[] ksPassword) throws KeyStoreException {
        Enumeration e = ks.aliases();
        String keyAlias = null;
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            if(ks.isKeyEntry(alias)) {
                keyAlias = alias;
            }
        }
        if(keyAlias == null)
            return "no keyalias in keystore";
        else
            return keyAlias;
    }
}
