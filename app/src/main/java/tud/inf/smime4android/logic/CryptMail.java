package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

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
            key = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
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
     * @param privkeypasswd password for the private key, can be null of it is not set
     * @return plaintext
     * @throws MessagingException in case of issues with the p7m inputstream
     * @throws IOException if a problem occurred while reading from the p12 stream
     */
    public byte[] decrypt(InputStream p7m, InputStream p12, char[] passwd, char[] privkeypasswd) throws MessagingException, IOException {
        byte[] decryptedByteData = new byte[0];
        Certificate cert = null;
        PrivateKey privateKey = null;

        try {
			KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
			ks.load(p12, passwd);

            Enumeration<String> aliases = ks.aliases();

            while((cert == null || privateKey == null) && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                cert = ks.getCertificate(alias);
                privateKey = (PrivateKey) ks.getKey(alias, privkeypasswd);
            }

			X509Certificate x509Cert = (X509Certificate) cert;

			MimeBodyPart encryptedMimeBodyPart = new MimeBodyPart(p7m);
			SMIMEEnveloped enveloped = new SMIMEEnveloped(encryptedMimeBodyPart);

			// look for our recipient identifier
			RecipientId recipientId = new JceKeyTransRecipientId(x509Cert);

			RecipientInformationStore recipients = enveloped.getRecipientInfos();
			RecipientInformation recipientInfo = recipients.get(recipientId);

			if(recipientInfo != null) {
            	JceKeyTransRecipient rec = new JceKeyTransEnvelopedRecipient(privateKey);
            	rec.setProvider(BouncyCastleProvider.PROVIDER_NAME);
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

    /**
     * Decrypt the p7m file with the help of the private key from the local keystore.
     * @param p7m the file to decrypt
     * @param keyalias alias of the private key, in case of empty String ("") the first private key
     *                 found in keystore will be taken
     * @param keystorepasswd password for the local keystore
     * @param privkeypasswd password for the private key, can be null of it is not set
     * @return plaintext a byte[0] in case no keystore exists
     * @throws MessagingException in case of an issues with the p7m inputstream
     */
    public byte[] decrypt(InputStream p7m, String keyalias, char[] keystorepasswd, char[] privkeypasswd) throws MessagingException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException, CMSException {
        byte[] decryptedByteData = new byte[0];
        Certificate cert = null;
        PrivateKey privateKey = null;

        KeyStoreHandler ksh = new KeyStoreHandler(this.context);
        if(ksh.exists()) {
            ksh.load(keystorepasswd);

            if(keyalias.equals("")) {
                Enumeration<String> aliases = ksh.getAliases();

                while ((cert == null || privateKey == null) && aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if(cert == null)
                        cert = ksh.getCertificate(alias);
                    if(privateKey == null)
                        privateKey = ksh.getPrivateKey(alias, privkeypasswd);
                }
            }
            else {
                cert = ksh.getCertificate(keyalias);
                privateKey = ksh.getPrivateKey(keyalias, privkeypasswd);
            }

            X509Certificate x509Cert = (X509Certificate) cert;

            MimeBodyPart encryptedMimeBodyPart = new MimeBodyPart(p7m);
            SMIMEEnveloped enveloped = new SMIMEEnveloped(encryptedMimeBodyPart);

            // look for our recipient identifier
            RecipientId recipientId = new JceKeyTransRecipientId(x509Cert);

            RecipientInformationStore recipients = enveloped.getRecipientInfos();
            RecipientInformation recipientInfo = recipients.get(recipientId);

            if (recipientInfo != null) {
                JceKeyTransRecipient rec = new JceKeyTransEnvelopedRecipient(privateKey);
                rec.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
                decryptedByteData = recipientInfo.getContent(rec);
                //decryptedByteData = Base64.decode(decryptedByteData);
            }
        }

        return decryptedByteData;
    }
}