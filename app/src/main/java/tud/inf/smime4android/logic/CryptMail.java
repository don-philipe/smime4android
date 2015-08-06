package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

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
     *
     * @param ksFile
     * @param ksPassword
     * @param keyAlias
     * @param msgContent
     * @return
     */
    public MimeMessage encrypt(String ksFile, char[] ksPassword, String keyAlias, String msgContent) {
        KeyStoreHandler ksh = new KeyStoreHandler(this.context, ksFile, ksPassword);
        String provider = this.context.getResources().getString(R.string.ks_provider);
        if (Security.getProvider(provider) == null)
            Security.addProvider(new BouncyCastleProvider());

        // create the generator for creating an smime/encrypted message
        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        try {
            Certificate[] chain = ksh.getCertChain(keyAlias);
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator((X509Certificate) chain[0]).setProvider(provider));
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        // version 3 only.
        /*
        MessageDigest dig = MessageDigest.getInstance("SHA1", provider);
        dig.update(cert.getPublicKey().getEncoded());
        gen.addKeyTransRecipient(cert.getPublicKey(), dig.digest());
        */

        // Get a Session object and create the mail message
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);
        // create the base for our message
        MimeMessage msg = new MimeMessage(session);
        MimeMessage body = new MimeMessage(session);

        try {
            msg.setText(msgContent);
            msg.saveChanges();

            MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC).setProvider(provider).build());

            Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
            Address toUser = new InternetAddress("example@bouncycastle.org");

            body.setFrom(fromUser);
            body.setRecipient(Message.RecipientType.TO, toUser);
            body.setSubject("example encrypted message");
            body.setContent(mp.getContent(), mp.getContentType());
            body.saveChanges();
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (SMIMEException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return body;
    }

    /**
     *
     * @param ksFile keystore filename
     * @param ksPassword password of the keystore
     * @param alias alias for private key and certificate chain
     * @param content a base64 encoded string representing the encrypted mailtext
     * @return the decrypted ciphertext
     */
    public String decrypt(String ksFile, char[] ksPassword, String alias, String content) {
        String mailtext = "decrypted mail";
        String provider = this.context.getResources().getString(R.string.ks_provider);
        if (Security.getProvider(provider) == null)
            Security.addProvider(new BouncyCastleProvider());
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props);

    /*    SMIMEEnveloped m = null;
        MimeMessage msg = null;
        try {
            msg = new MimeMessage(session, is);
         //   m = new SMIMEEnveloped(msg);
        } catch (MessagingException e1) {
            e1.printStackTrace();
      //  } catch (CMSException e1) {
       //     e1.printStackTrace();
        }*/

//        MimeBodyPart res = new MimeBodyPart();
//        MimeMultipart mm = (MimeMultipart) m.getEncryptedContent();
/*
        MimeMessage body = new MimeMessage(session);
        try {
            body.setFrom(msg.getFrom().toString());
            // assume there is only one recipient
            body.setRecipient(Message.RecipientType.TO, msg.getAllRecipients()[0]);
            body.setSubject(msg.getSubject());
            body.setContent(msg, msg.getContentType());
            body.saveChanges();
        } catch (MessagingException e) {
            e.printStackTrace();
        }*/

        Certificate[] reciCert = null;
        PrivateKey privKey = null;
        try {
            KeyStoreHandler ksh = new KeyStoreHandler(this.context, ksFile, ksPassword);
            List<X509Certificate> x509 = ksh.getAllCertificates();
            reciCert = ksh.getCertChain(alias);
            privKey = ksh.getPrivKey(alias);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        MimeBodyPart body = null;
        try {
            // set empty header to avoid NullPointerException in toolkit.decrypt
            InternetHeaders ih = new InternetHeaders();
            ih.addHeaderLine("");
            body = new MimeBodyPart(ih, Base64.decode(content));
        } catch (MessagingException e) {
            e.printStackTrace();
        }
       if(reciCert != null && privKey != null) {
           MimeBodyPart dec = new MimeBodyPart();
           try {
               JceKeyTransRecipientId jktci = new JceKeyTransRecipientId((X509Certificate)reciCert[0]);
               JceKeyTransEnvelopedRecipient jkter = new JceKeyTransEnvelopedRecipient(privKey);
               jkter.setProvider(provider);
               dec = toolkit.decrypt(body, jktci , jkter);
               if(dec == null)
                   mailtext = "recipient ID cannot be matched";
               else
                   mailtext = dec.getContent().toString();
           } catch (SMIMEException e) {
               e.printStackTrace();
           } catch (MessagingException e) {
               e.printStackTrace();
           } catch (IOException e) {
               e.printStackTrace();
           }
       } else {
           mailtext = "missing recipient certificate and private key";
       }
       return mailtext;
    }
}