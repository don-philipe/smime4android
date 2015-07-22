package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import tud.inf.smime4android.R;


/**
 * Created by don on 24.06.15.
 */
public class KeyStoreHandler {

    private Context context;
    private String ks_type;
    private String ks_provider;

    public KeyStoreHandler(Context context) {
        this.context = context;
        this.ks_type = this.context.getResources().getString(R.string.ks_type);
        this.ks_provider = this.context.getResources().getString(R.string.ks_provider);
    }

    /**
     *
     * @param ksFileName
     * @param password for the keystore
     */
    public void initKeyStore(String ksFileName, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
            ks.load(null, password);
            this.storeKeyStore(ks, ksFileName, password);
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
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     */
    public boolean keyStorePresent(File keystorefile, char[] ksPassword) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
        try {
            ks.load(new FileInputStream(this.context.getFilesDir() + "/" + keystorefile), ksPassword);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     *
     * @param ksFileName
     * @param ksPassword
     * @param alias key alias
     * @param certs certificate chain where certs[0] is the clients certificate, certs[1] ... certs[n] are intermediate certificates and certs[n+1] is the root certificate
     * @param privkey
     * @param keyPassword
     */
    public void addCertificate(String ksFileName, char[] ksPassword, String alias, Certificate[] certs, PrivateKey privkey, char[] keyPassword) {
        try {
            KeyStore ks = this.loadKeyStore(ksFileName, ksPassword);
            ks.setKeyEntry(alias, privkey, keyPassword, certs);
            this.storeKeyStore(ks, ksFileName, ksPassword);
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
     *
     * @param ksFileName
     * @param ksPassword
     * @return null in case something went wrong while loading keystorefile
     * @throws
     */
    public List<X509Certificate> getAllCertificates(String ksFileName, char[] ksPassword) throws NoSuchFieldException {
        List<X509Certificate> certlist = new LinkedList<X509Certificate>();
        try {
            KeyStore ks = this.loadKeyStore(ksFileName, ksPassword);
            if(ks != null) {
                List<String> keyAliases = getAllKeyAliases(ksFileName, ksPassword);
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
     * @param ksFileName
     * @param ksPassword
     * @return
     * @throws NoSuchFieldException
     */
    public PrivateKey getPrivKey(String ksFileName, char[] ksPassword, String alias) throws NoSuchFieldException{
        try {
            KeyStore ks = this.loadKeyStore(ksFileName, ksPassword);
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
     * @param ksFileName
     * @param ksPassword
     * @param alias
     * @return
     */
    public boolean removeCertificate(String ksFileName, char[] ksPassword, String alias) {
        boolean success = false;
        KeyStore ks = null;
        try {
             ks = this.loadKeyStore(ksFileName, ksPassword);
            if(ks.isCertificateEntry(alias)) {
                ks.deleteEntry(alias);
                this.storeKeyStore(ks, ksFileName, ksPassword);
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
     * @param ksFileName
     * @param ksPassword
     * @param alias
     * @return
     */
    public boolean removePrivKey(String ksFileName, char[] ksPassword, String alias) {
        boolean success = false;
        try {
            KeyStore ks = this.loadKeyStore(ksFileName, ksPassword);
            if(ks.isKeyEntry(alias)) {
                ks.deleteEntry(alias);
                this.storeKeyStore(ks, ksFileName, ksPassword);
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
     * @param ksFileName
     * @param ksPassword
     * @return can be null
     * @throws NoSuchFieldException
     */
    protected KeyStore loadKeyStore(String ksFileName, char[] ksPassword) throws NoSuchFieldException {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(this.ks_type, this.ks_provider);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        try {
            String path = this.context.getFilesDir() + "/";
            InputStream inputStream = this.context.openFileInput(path + ksFileName);
            ks.load(inputStream, ksPassword);
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
     * @param ksFileName
     * @param ksPassword
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    protected void storeKeyStore(KeyStore ks, String ksFileName, char[] ksPassword) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        OutputStream outputStream = this.context.openFileOutput(ksFileName, Context.MODE_PRIVATE);
        ks.store(outputStream, ksPassword);
        outputStream.close();
    }

    /**
     *
     * @param ksFileName
     * @param ksPassword
     * @return
     * @throws KeyStoreException
     */
    protected List<String> getAllKeyAliases(String ksFileName, char[] ksPassword) throws KeyStoreException {
        KeyStore ks = null;
        try {
            ks = this.loadKeyStore(ksFileName, ksPassword);
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
        if(keyAliases.isEmpty())
            return null;
        else
            return keyAliases;
    }

    /**
     *
     * @param pubKey
     * @param privKey
     * @param issuer "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate"
     * @param subject "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate"
     * @return
     * @throws Exception
     */
    protected Certificate createMasterCert(PublicKey pubKey, PrivateKey privKey, String issuer, String subject) throws Exception {
        // create the certificate - version 1
        X509v1CertificateBuilder v1Bldr = new JcaX509v1CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            new X500Name(subject), pubKey);

        //TODO signaturealgorithm
        X509CertificateHolder certHldr = v1Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(this.ks_provider).build(privKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(this.ks_provider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("root certificate"));

        return cert;
    }

    /**
     *
     * @param pubKey
     * @param caPrivKey
     * @param caCert
     * @param issuedTo [0]:C (country code), [1]:O (Organization), [2]:OU (Organizational Unit), [3]:mailaddress
     * @return
     * @throws Exception
     */
    protected Certificate createIntermediateCert(PublicKey pubKey, PrivateKey caPrivKey, X509Certificate caCert, String[] issuedTo) throws Exception {
        // subject name builder.
        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.C, issuedTo[0]);
        nameBuilder.addRDN(BCStyle.O, issuedTo[1]);
        nameBuilder.addRDN(BCStyle.OU, issuedTo[2]);
        nameBuilder.addRDN(BCStyle.EmailAddress, issuedTo[3]);

        // create the certificate - version 3
        X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(caCert, BigInteger.valueOf(2),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            nameBuilder.build(), pubKey);

        // extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3Bldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        v3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        v3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        //TODO signaturealgorithm
        X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(this.ks_provider).build(caPrivKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(this.ks_provider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("intermediate certificate"));

        return cert;
    }

    /**
     *
     * @param pubKey
     * @param caPrivKey
     * @param caPubKey
     * @param signer [0]:C (country code), [1]:O (Organization), [2]:OU (Organizational Unit), [3]:mailaddress
     * @param subject [0]:C, [1]:O, [2]:L (Locality Name), [3]:CN (Common Name), [4]:mailaddress
     * @return
     * @throws Exception
     */
    protected Certificate createCert(PublicKey pubKey, PrivateKey caPrivKey, PublicKey caPubKey, String[] signer, String[] subject) throws Exception {
        // signers name table.
        X500NameBuilder issuerBuilder = new X500NameBuilder();
        issuerBuilder.addRDN(BCStyle.C, signer[0]);
        issuerBuilder.addRDN(BCStyle.O, signer[1]);
        issuerBuilder.addRDN(BCStyle.OU, signer[2]);
        issuerBuilder.addRDN(BCStyle.EmailAddress, signer[3]);

        // subjects name table.
        X500NameBuilder subjectBuilder = new X500NameBuilder();
        subjectBuilder.addRDN(BCStyle.C, subject[0]);
        subjectBuilder.addRDN(BCStyle.O, subject[1]);
        subjectBuilder.addRDN(BCStyle.L, subject[2]);
        subjectBuilder.addRDN(BCStyle.CN, subject[3]);
        subjectBuilder.addRDN(BCStyle.EmailAddress, subject[4]);

        // create the certificate - version 3
        X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(issuerBuilder.build(), BigInteger.valueOf(3),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            subjectBuilder.build(), pubKey);

        // extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3Bldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));

        v3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caPubKey));
        //TODO signaturealgorithm
        X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(this.ks_provider).build(caPrivKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(this.ks_provider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(caPubKey);

        PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;

        // this is also optional - in the sense that if you leave this
        // out the keystore will add it automatically, note though that
        // for the browser to recognise the associated private key this
        // you should at least use the pkcs_9_localKeyId OID and set it
        // to the same as you do for the private key's localKeyId.
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("client key"));
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        return cert;
    }
}
