package tud.inf.smime4android.logic;

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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by don on 30.07.15.
 */
public class KeyStoreUtil {

    /**
     *
     * @param pubKey
     * @param privKey
     * @param issuer "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate"
     * @param subject "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate"
     * @param ksProvider
     * @return
     * @throws Exception
     */
    public static Certificate createMasterCert(PublicKey pubKey, PrivateKey privKey, String issuer, String subject, String ksProvider) throws Exception {
        // create the certificate - version 1
        X509v1CertificateBuilder v1Bldr = new JcaX509v1CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
                new X500Name(subject), pubKey);

        //TODO signaturealgorithm
        X509CertificateHolder certHldr = v1Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(ksProvider).build(privKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(ksProvider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        //TODO: this cast throws exception:
//        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;
//        // this is actually optional - but if you want to have control
//        // over setting the friendly name this is the way to do it...
//        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("root certificate"));

        return cert;
    }

    /**
     *
     * @param pubKey
     * @param caPrivKey
     * @param caCert
     * @param issuedTo [0]:C (country code), [1]:O (Organization), [2]:OU (Organizational Unit), [3]:mailaddress
     * @param ksProvider
     * @return
     * @throws Exception
     */
    public static Certificate createIntermediateCert(PublicKey pubKey, PrivateKey caPrivKey, X509Certificate caCert, String[] issuedTo, String ksProvider) throws Exception {
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
        X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(ksProvider).build(caPrivKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(ksProvider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

//        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;
//        // this is actually optional - but if you want to have control
//        // over setting the friendly name this is the way to do it...
//        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("intermediate certificate"));

        return cert;
    }

    /**
     *
     * @param pubKey
     * @param caPrivKey
     * @param caPubKey
     * @param signer [0]:C (country code), [1]:O (Organization), [2]:OU (Organizational Unit), [3]:mailaddress
     * @param subject [0]:C, [1]:O, [2]:L (Locality Name), [3]:CN (Common Name), [4]:mailaddress
     * @param ksProvider
     * @return
     * @throws Exception
     */
    public static Certificate createCert(PublicKey pubKey, PrivateKey caPrivKey, PublicKey caPubKey, String[] signer, String[] subject, String ksProvider) throws Exception {
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
        X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(ksProvider).build(caPrivKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(ksProvider).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(caPubKey);

//        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;
//
//        // this is also optional - in the sense that if you leave this
//        // out the keystore will add it automatically, note though that
//        // for the browser to recognise the associated private key this
//        // you should at least use the pkcs_9_localKeyId OID and set it
//        // to the same as you do for the private key's localKeyId.
//        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("client key"));
//        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));

        return cert;
    }
}
