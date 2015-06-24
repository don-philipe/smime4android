package tud.inf.smime4android;

import android.net.Uri;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

/**
 * Created by don on 17.06.15.
 */
public class DecryptMail {

    /**
     *
     * @param data
     * @param ksPassword
     * @return
     */
    public static String decrypt(Uri data, char[] ksPassword) {
        //X509Certificate reciCert, PrivateKey privKey
        String mailtext = "decrypted mail";

        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        SMIMEEnveloped m = null;
        MimeMessage msg = null;
        try {
            File file = new File(data.toString());
            FileInputStream fis = new FileInputStream(file);
            msg = new MimeMessage(session, fis);
            m = new SMIMEEnveloped(msg);
        } catch (MessagingException e1) {
            e1.printStackTrace();
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        } catch (CMSException e1) {
            e1.printStackTrace();
        }

//        MimeBodyPart res = new MimeBodyPart();
//        MimeMultipart mm = (MimeMultipart) m.getEncryptedContent();

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
        }

        X509Certificate reciCert = null;
        PrivateKey privKey = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS7", "BC");
            File keystorefile = new File("key.store");
            if(keystorefile.exists()) {
                ks.load(new FileInputStream(keystorefile), ksPassword);
                Enumeration e = ks.aliases();
                String keyAlias = null;
                while (e.hasMoreElements()) {
                    String alias = (String) e.nextElement();
                    if(ks.isKeyEntry(alias)) {
                        keyAlias = alias;
                    }
                }
                if(keyAlias == null)
                    return "no keyalias in keystore";
                reciCert = (X509Certificate) ks.getCertificate(keyAlias);
                privKey = (PrivateKey) ks.getKey(keyAlias, null);
            }
            else
                return "no keystore file present";
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
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        MimeBodyPart dec = new MimeBodyPart();
        try {
            dec = toolkit.decrypt(body, new JceKeyTransRecipientId(reciCert), new JceKeyTransEnvelopedRecipient(privKey).setProvider("BC"));
        } catch (SMIMEException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        }

        mailtext = dec.toString();

        return mailtext;
    }
}