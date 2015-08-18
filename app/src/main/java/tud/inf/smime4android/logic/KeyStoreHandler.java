package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
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
    private final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private KeyStore ks;

    public KeyStoreHandler(Context context) {
        this.context = context;
        ks = null;
    }

    /**
     *
     */
    public void initKeyStore() {
        ks = null;
        try {
            ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }


    public int keyStoreSize() {
        int result = 0;
        try {
           result = ks.size();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return result;
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
//        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
//        File keystorefile = new File(this.ksFileName);
//        try {
//            ks.load(new FileInputStream(this.context.getFilesDir() + "/" + keystorefile), this.ksPassword);
//            return true;
//        } catch (IOException e) {
//            e.printStackTrace();
//            return false;
//        }
        return true;
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
            ks.setKeyEntry(alias, privkey, null, certs);
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
     * @param alias
     * @param pubKey
     * @param certs
     */
    public void addPubKey(String alias, PublicKey pubKey, Certificate[] certs) {
        try {
            KeyStore ks = this.loadKeyStore();
            ks.setKeyEntry(alias, pubKey, null, certs);
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
        Certificate[] certArray;
        try {
            if(ks != null) {
                List<String> allAliases = this.getAllAliases();
                for(String s : allAliases) {

                        certArray = ks.getCertificateChain(s);
                        for (int i = 0; i < certArray.length; i++){
                            certlist.add((X509Certificate) certArray[i]);
                        }
//                        certlist.add((X509Certificate) ks.getCertificate(s));

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
     * @param alias for private key
     * @param passwd private key password
     * @return private key if present, null otherwise
     * @throws NoSuchFieldException
     */
    public PrivateKey getPrivKey(String alias, char[] passwd) throws NoSuchFieldException{
        try {
            KeyStore ks = this.loadKeyStore();
            if(ks != null) {
                return (PrivateKey) ks.getKey(alias, passwd);
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

        try {
                ks.deleteEntry(alias);
                this.storeKeyStore(ks);
                success = true;


        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
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
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
//        try {
//            InputStream inputStream = this.context.openFileInput(this.ksFileName);
//            ks.load(inputStream, this.ksPassword);
//            inputStream.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        }
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
//        OutputStream outputStream = this.context.openFileOutput(this.ksFileName, Context.MODE_PRIVATE);
//        ks.store(outputStream, this.ksPassword);
//        outputStream.flush();
//        outputStream.close();
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
     * Load a pkcs12 file, usually ending with ".p12".
     * Private keys which have already a password will be protected with the same password in local
     * keystore.
     * @param byteArrayInputStream input stream to pkcs12 file.
     * @param ksPasswd password to pkcs12 file.
     * @param privKeyPasswd password to recover the private key.
     * @throws IOException if a problem occurred while reading from the stream.
     * @throws CertificateException if an exception occurred while loading the certificates of this
     * KeyStore.
     * @throws UnrecoverableKeyException in case the private key cannot be recovered, usually this
     * is the case when the wrong password is passed.
     */
    public void importPkcs12File(ByteArrayInputStream byteArrayInputStream, char[] ksPasswd, char[] privKeyPasswd)
            throws IOException, CertificateException, UnrecoverableKeyException {
        String provider = this.context.getResources().getString(R.string.ks_provider);
        if (Security.getProvider(provider) == null)
            Security.addProvider(new BouncyCastleProvider());
        try {
            KeyStore pkcs12 = KeyStore.getInstance("PKCS12", provider);
            pkcs12.load(byteArrayInputStream, ksPasswd);
            Enumeration<String> e = pkcs12.aliases();
            while(e.hasMoreElements()) {
                String alias = e.nextElement();
                Certificate[] certchain = pkcs12.getCertificateChain(alias);
                PrivateKey pk = (PrivateKey) pkcs12.getKey(alias, privKeyPasswd);
                if(pk != null)
                    this.ks.setKeyEntry(alias, pk, privKeyPasswd, certchain);
                else if(certchain != null)   // its just an intermediate or root certificate we got
                    this.ks.setCertificateEntry(alias, certchain[0]);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Return every alias, no matter if its a certificate or a key alias.
     * @return can return empty list if no aliases present in the keystore
     * @throws KeyStoreException
     */
    protected List<String> getAllAliases() throws KeyStoreException {
        Enumeration e = ks.aliases();
        List<String> keyAliases = new LinkedList<String>();
        while (e.hasMoreElements()) {
            keyAliases.add((String) e.nextElement());
        }
        return keyAliases;
    }

}
