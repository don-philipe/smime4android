package tud.inf.smime4android.logic;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.LinkedList;
import java.util.List;

import tud.inf.smime4android.R;


/**
 * Created by don on 24.06.15.
 */
public class KeyStoreHandler {

    private Context context;
    private final String ks_type;
    private final String ks_provider;
    private final String ksFileName;
    private final char[] ksPassword;

    public KeyStoreHandler(Context context, String fileName, char[] password) {
        this.context = context;
        this.ks_type = this.context.getResources().getString(R.string.ks_type);
        this.ks_provider = this.context.getResources().getString(R.string.ks_provider);
        this.ksFileName = fileName;
        this.ksPassword = password;
    }

    /**
     *
     */
    public void initKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
            ks.load(null, this.ksPassword);
            this.storeKeyStore(ks);
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
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     */
    public boolean keyStorePresent() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
        File keystorefile = new File(this.ksFileName);
        try {
            ks.load(new FileInputStream(this.context.getFilesDir() + "/" + keystorefile), this.ksPassword);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Adds the private key with password and corresponding certificate chain to the keystore.
     * @param alias key alias
     * @param certs certificate chain where certs[0] is the clients certificate, certs[1] ... certs[n] are intermediate certificates and certs[n+1] is the root certificate
     * @param privkey
     * @param keyPassword password for the private key
     */
    public void addPrivKeyAndCertificate(String alias, Certificate[] certs, PrivateKey privkey, char[] keyPassword) {
        try {
            KeyStore ks = this.loadKeyStore();
            ks.setKeyEntry(alias, privkey, keyPassword, certs);
            this.storeKeyStore(ks);
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
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    /**
     * Adds a single certificate e.g. a root certificate to the keystore.
     * @param alias name under which the certificate can be found in the keystore
     * @param cert the certificate itself
     */
    public void addCertificate(String alias, Certificate cert) {
        try {
            KeyStore ks = this.loadKeyStore();
            ks.setCertificateEntry(alias, cert);
            this.storeKeyStore(ks);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @return null in case something went wrong while loading keystorefile
     * @throws
     */
    public List<X509Certificate> getAllCertificates() throws NoSuchFieldException {
        List<X509Certificate> certlist = new LinkedList<X509Certificate>();
        try {
            KeyStore ks = this.loadKeyStore();
            if(ks != null) {
                List<String> keyAliases = this.getAllAliases();
                for(String s : keyAliases) {
                    certlist.add((X509Certificate) ks.getCertificate(s));
                }
            }
            else
                throw new NoSuchFieldException("can't get keystore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return certlist;
    }

    /**
     *
     * @param alias
     * @return
     * @throws NoSuchFieldException
     */
    public PrivateKey getPrivKey(String alias) throws NoSuchFieldException{
        try {
            KeyStore ks = this.loadKeyStore();
            if(ks != null) {
                return (PrivateKey) ks.getKey(alias, null);
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
     * @param alias
     * @return
     */
    public boolean removeCertificate(String alias) {
        boolean success = false;
        KeyStore ks = null;
        try {
             ks = this.loadKeyStore();
            if(ks.isCertificateEntry(alias)) {
                ks.deleteEntry(alias);
                this.storeKeyStore(ks);
                success = true;
            }
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return success;
    }

    /**
     *
     * @param alias
     * @return
     */
    public boolean removePrivKey(String alias) {
        boolean success = false;
        try {
            KeyStore ks = this.loadKeyStore();
            if(ks.isKeyEntry(alias)) {
                ks.deleteEntry(alias);
                this.storeKeyStore(ks);
                success = true;
            }
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return success;
    }

    /**
     *
     * @return can be null
     * @throws NoSuchFieldException
     */
    protected KeyStore loadKeyStore() throws NoSuchFieldException {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        try {
            InputStream inputStream = this.context.openFileInput(this.ksFileName);
            ks.load(inputStream, this.ksPassword);
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return ks;
    }

    /**
     * If anything goes wrong exceptions will be thrown.
     * @param ks
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    protected void storeKeyStore(KeyStore ks) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        OutputStream outputStream = this.context.openFileOutput(this.ksFileName, Context.MODE_PRIVATE);
        ks.store(outputStream, this.ksPassword);
        outputStream.flush();
        outputStream.close();
    }

    /**
     * Returns number of entries in keystore.
     * @return number of entries stored in keystore.
     * @throws KeyStoreException
     */
    public int getKeyStoreSize() throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return ks.size();
    }

    /**
     * Tests if an alias is present in the keystore
     * @param alias the alias to search for
     * @return wheather alias is present or not
     * @throws KeyStoreException if keystore is not initialized
     */
    public boolean containsAlias(String alias) throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return ks.containsAlias(alias);
    }

    /**
     * Gives you a single certificate which is associated with the given alias.
     * Can't give you individual certificates from a certificate chain.
     * @param alias
     * @return
     * @throws KeyStoreException
     */
    public Certificate getSingleCert(String alias) throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return ks.getCertificate(alias);
    }

    /**
     * Gives you a certificate chain associated with the given alias. But returns nothing if the alias
     * belongs to a certificate that was saved as a individual one.
     * @param alias alias of the certificate chain
     * @return certificate chain in the following form: chain[0] - user cert, chain[1...n] intermediate certs, chain[n+1] root cert
     * @throws KeyStoreException if keystore is not initialized
     */
    public Certificate[] getCertChain(String alias) throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return ks.getCertificateChain(alias);
    }

    /**
     *
     * @return can return empty list if no aliases present in the keystore
     * @throws KeyStoreException
     */
    protected List<String> getAllAliases() throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        Enumeration e = ks.aliases();
        List<String> keyAliases = new LinkedList<String>();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            if(ks.isKeyEntry(alias)) {
                keyAliases.add(alias);
            }
        }
        return keyAliases;
    }
}
