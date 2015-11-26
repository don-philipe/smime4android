package tud.inf.smime4android.logic;

import android.content.Context;

import com.sun.mail.util.ASCIIUtility;

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
import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
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
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.SharedInputStream;

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
    public byte[] decrypt(InputStream p7m, String keyalias, char[] keystorepasswd, char[] privkeypasswd)
            throws MessagingException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException, CMSException, NoKeyPresentException {
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
                    if(privateKey == null) //TODO hier den KeyEntry raussuchen
                        privateKey = ksh.getPrivateKey(alias, privkeypasswd);
                }
            }
            else {
                cert = ksh.getCertificate(keyalias);
                privateKey = ksh.getPrivateKey(keyalias, privkeypasswd);
            }

            if(privateKey == null)
                throw new NoKeyPresentException("No key bind on alias " + keyalias);
            else {

                X509Certificate x509Cert = (X509Certificate) cert;

                MimeBodyPart encryptedMimeBodyPart = null;
                byte[] ciphertext = readBytes(p7m);
                if(!hasHeaders(ciphertext)) {
                    InternetHeaders headers = new InternetHeaders();
                    headers.setHeader("Content-Type", "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data");
                    headers.setHeader("Content-Transfer-Encoding", "base64");
                    headers.setHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
                    headers.setHeader("Content-Description", "S/MIME Encrypted Message");

                    encryptedMimeBodyPart = new MimeBodyPart(headers, Base64.encode(ciphertext));
                }else{
                    InternetHeaders headers = new InternetHeaders();
                    String content = new String(ciphertext);
                    while(content.indexOf('\n')>1) {
                        if (content.startsWith("Content")) {
                            String header = content.substring(0, content.indexOf('\n')-1);
                            content = content.substring(content.indexOf('\n')+1);
                            String name = header.substring(0,header.indexOf(':'));
                            String value = header.substring(header.indexOf(':')+1);
                            headers.setHeader(name, value);
                        }
                    }
                    content = content.substring(2);
                    encryptedMimeBodyPart = new MimeBodyPart(headers, content.getBytes());
//                    encryptedMimeBodyPart = new MimeBodyPart(p7m);
                }
                SMIMEEnveloped enveloped =null;
                try {
                     enveloped = new SMIMEEnveloped(encryptedMimeBodyPart);
                }catch(Exception e){
                    e.printStackTrace();
                }

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
        }

        return decryptedByteData;
    }

    public boolean hasHeaders(byte[] content) throws FileNotFoundException{
        String header = "Content-Type: application/pkcs7-mime;";// name=\"smime.p7m\"; smime-type=enveloped-data\n" +
//                "Content-Transfer-Encoding: base64\n" +
//                "Content-Disposition: attachment; filename=\"smime.p7m\"\n" +
//                "Content-Description: S/MIME Encrypted Message\n\n";

//        Writer fw = null;
//        try {
//            fw = new FileWriter("smime.p7m");
//            fw.write(header);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        finally{
//            if(fw!=null)
//                try{fw.close();} catch(IOException e){e.printStackTrace();}
//        }
//        byte[] content=null;
//        try {
//            content = readBytes(p7m);
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        }

        String inhalt = new String(content);
        if(inhalt.startsWith(header)){
            return true;
        }else {
            return false;
        }
    }

    private byte[] readBytes(InputStream is) throws MessagingException {
        if(!(is instanceof ByteArrayInputStream) && !(is instanceof BufferedInputStream) && !(is instanceof SharedInputStream)) {
            is = new BufferedInputStream((InputStream)is);
        }

        //this.headers = new InternetHeaders((InputStream)is);
        if(is instanceof SharedInputStream) {
            SharedInputStream ioex = (SharedInputStream)is;
        //    this.contentStream = ioex.newStream(ioex.getPosition(), -1L);
        } else {
            try {
                return ASCIIUtility.getBytes((InputStream)is);
            } catch (IOException var3) {
                throw new MessagingException("Error reading input stream", var3);
            }
        }
        return null;
    }
}