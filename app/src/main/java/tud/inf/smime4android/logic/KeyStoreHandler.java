package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import tud.inf.smime4android.R;


/**
 * This class stores keys, especially the private key, and certificates permanently.
 * Created by don on 24.06.15.
 */
public class KeyStoreHandler {

    private Context context;
    private final String keystorefile;
    private KeyStore ks;
    private char[] passwd;

    /**
     *
     * @param context app context
     * @throws KeyStoreException in case of error while getting keystore instance.
     */
    public KeyStoreHandler(Context context) throws KeyStoreException {
        this.context = context;

        this.keystorefile = this.context.getResources().getString(R.string.ks_filename);
        try {
            this.ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Just for checking if it should be promted for an existing password or a new password for a new
     * keystore. Existence should be checked when starting app.
     * @return true for existing, false for not existing keystore file
     */
    public boolean exists() {
        try {
            this.context.openFileInput(this.keystorefile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Loads existing keystore. If no one exists, creates a new one.
     * @param passwd password for keystore
     * @return true in case of successfully loading an existing keystore, false in case of successfully
     * creating (not-loading) a keystore
     * @throws CertificateException in case of error with loading certificate from store.
     */
    public boolean load(char[] passwd) throws CertificateException, IOException {
        this.passwd = passwd;
        try {
            InputStream inputStream = this.context.openFileInput(this.keystorefile);
            this.ks.load(inputStream, this.passwd);
        } catch (FileNotFoundException e) {
            try {
                this.ks.load(null, this.passwd);
                return true;
            } catch (IOException e1) {
                e1.printStackTrace();
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            }
            return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return true;
    }

    /**
     *
     * @return false in case something went wrong with writing the file. Stacktrace will be printed as well.
     * @throws CertificateException if something is wrong with the certificate to be written.
     * @throws KeyStoreException if the keystore is not initialized.
     */
    public boolean storeKeyStore() throws CertificateException, KeyStoreException {
        try {
            OutputStream outputStream = this.context.openFileOutput(this.keystorefile, Context.MODE_PRIVATE);
            this.ks.store(outputStream, this.passwd);
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * The imported PKCS#12 file should only contain one private key and one certificate. In other
     * words, only one alias should exist in the file.
     * @param p12 the PKCS#12 file
     * @param pkcs12Passwd the password protecting the PKCS#12 file
     * @param privKeyPasswd password for private key if necessary, can be null in case no one is set.
     * @throws KeyStoreException in case something went wrong with getting keystore instance or keystore
     * cannot be initialized.
     * @throws IOException if the p12 inputstream cannot be read.
     * @throws UnrecoverableKeyException if key cannot be recovered
     */
    public void importPKCS12(InputStream p12, char[] pkcs12Passwd, char[] privKeyPasswd) throws KeyStoreException,
            IOException, UnrecoverableKeyException {
        try {
            KeyStore pkcs12 = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            pkcs12.load(p12, pkcs12Passwd);
            Enumeration<String> aliases = pkcs12.aliases();
            while(aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                this.ks.setCertificateEntry(alias, pkcs12.getCertificate(alias));
                this.ks.setKeyEntry(alias,
                        pkcs12.getKey(alias, privKeyPasswd),
                        privKeyPasswd,
                        new Certificate[]{pkcs12.getCertificate(alias)});
            }
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param alias for certificate
     * @return a certificate
     * @throws KeyStoreException if keystore is not initialized
     */
    public Certificate getCertificate(String alias) throws KeyStoreException {
        return this.ks.getCertificate(alias);
    }

    /**
     *
     * @param alias for private key
     * @param passwd can be null if none is set
     * @return the private key or null if something goes wrong
     * @throws UnrecoverableKeyException if key cant be recovered (e.g. wrong password)
     * @throws KeyStoreException if keystore is not initialized
     */
    public PrivateKey getPrivateKey(String alias, char[] passwd) throws UnrecoverableKeyException, KeyStoreException {
        PrivateKey privkey = null;
        try {
            privkey = (PrivateKey) this.ks.getKey(alias, passwd);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privkey;
    }

    /**
     *
     * @return all aliases present in keystore
     * @throws KeyStoreException in case keystore is not initialized
     */
    public Enumeration<String> getAliases() throws KeyStoreException {
        return this.ks.aliases();
    }
}
