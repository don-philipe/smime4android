package tud.inf.smime4android;

import org.bouncycastle.jce.provider.X509CertificateObject;

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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Created by don on 24.06.15.
 */
public class KeyStoreHandler {

    /**
     *
     * @param keystorefile
     * @param password
     */
    public static void initKeyStore(File keystorefile, char[] password) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12", "BC");
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
}
