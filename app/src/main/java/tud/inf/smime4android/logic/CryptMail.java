package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import tud.inf.smime4android.R;

/**
 * Has methods for en- and decrypting mails.
 * Created by don on 17.06.15.
 */
public class CryptMail {

    private Context context;

    /**
     *
     * @param context
     */
    public CryptMail(Context context) {
        this.context = context;
    }

    /**
     * Decrypts a smime encrypted mail (smime.p7m attachment) with the help of a private key in a
     * .pem file and a associated certificate in an additional .pem file.
     * @param p7m the p7m file to decrypt
     * @param certstream certificate of private key (pem file)
     * @param keystream private key (pem file)
     * @return the plaintext
     * @throws MessagingException in case of issues with the inputstream
     * @throws CMSException in case of malformed input
     */
    public byte[] decrypt(InputStream p7m, InputStream keystream, InputStream certstream) throws MessagingException, CMSException {
        Session session = Session.getDefaultInstance(System.getProperties(), null);
        MimeMessage message = new MimeMessage(session, p7m);
        SMIMEEnveloped env = new SMIMEEnveloped(message);
        RecipientInformationStore store = env.getRecipientInfos();

        X509Certificate cert = null;
        try {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                    .generateCertificate(certstream);
        } catch (CertificateException e) {
            System.err.println("X.509 certificates not supported with provider " + BouncyCastleProvider.PROVIDER_NAME +
                    " or parsing problem");
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.err.println("provider " + BouncyCastleProvider.PROVIDER_NAME + " not available");
            e.printStackTrace();
        }
        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(cert));

        PrivateKey key = null;
        try {
            key = new JcaPEMKeyConverter().setProvider("BC")
                    .getKeyPair((PEMKeyPair) (new PEMParser(new InputStreamReader(keystream))).readObject()).getPrivate();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return recipInfo.getContent(new JceKeyTransEnvelopedRecipient(key));
    }

    /**
     * Decrypts a smime encrypted mail (smime.p7m attachment) with the help of a PKCS#12 file which
     * must contain at least a private key and an associated certificate.
     * @param p7m the p7m file to decrypt
     * @param p12 the keystore with the private key inside
     * @param passwd the password for the p12 file
     * @return plaintext
     * @throws MessagingException in case of issues with the p7m inputstream
     * @throws IOException if a problem occurred while reading from the p12 stream
     */
    public byte[] decrypt(InputStream p7m, InputStream p12, char[] passwd) throws MessagingException, IOException {
        byte[] decryptedByteData = new byte[0];
        Certificate cert = null;
        PrivateKey privateKey = null;

        try {
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(p12, passwd);

            Enumeration<String> aliases = ks.aliases();

            while((cert == null || privateKey == null) && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                cert = ks.getCertificate(alias);
                privateKey = (PrivateKey) ks.getKey(alias, null);
            }

			X509Certificate x509Certificate = (X509Certificate) cert;

			MimeBodyPart encryptedMimeBodyPart = new MimeBodyPart(p7m);
			SMIMEEnveloped enveloped = new SMIMEEnveloped(encryptedMimeBodyPart);

			// look for our recipient identifier
			RecipientId recipientId = new JceKeyTransRecipientId(x509Certificate);

			RecipientInformationStore recipients = enveloped.getRecipientInfos();
			RecipientInformation recipientInfo = recipients.get(recipientId);

			if(recipientInfo != null) {
            	JceKeyTransRecipient rec = new JceKeyTransEnvelopedRecipient(privateKey);
            	rec.setProvider("BC");
            	rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
				decryptedByteData = recipientInfo.getContent(rec);
//				decryptedByteData = Base64.decode(decryptedByteData);
			}
		} catch (GeneralSecurityException e) {
            e.printStackTrace();
		} catch (CMSException e) {
            e.printStackTrace();
		}

        return decryptedByteData;
    }
}