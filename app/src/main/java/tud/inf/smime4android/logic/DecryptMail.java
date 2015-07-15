package tud.inf.smime4android.logic;

import android.content.Context;

import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

/**
 * Created by don on 17.06.15.
 */
public class DecryptMail {

    private Context context;

    /**
     *
     * @param context
     */
    public DecryptMail(Context context) {
        this.context = context;
    }

    /**
     *
     * @param ksFile path to the keystore file
     * @param ksPassword
     * @param is
     * @return
     */
    public String decrypt(String ksFile, char[] ksPassword, InputStream is, String content) {
        String mailtext = "decrypted mail";
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

        X509Certificate reciCert = null;
        PrivateKey privKey = null;
        try {
            KeyStoreHandler ksh = new KeyStoreHandler(this.context);
            List<X509Certificate> x509 = ksh.getAllCertificates(ksFile, ksPassword);
            //reciCert =
            privKey = ksh.getPrivKey(ksFile, ksPassword, "alias");
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }

        MimeBodyPart body = null;
        try {
            body = new MimeBodyPart(null, content.getBytes());

        } catch (MessagingException e) {
            e.printStackTrace();
        }
       if(reciCert!=null && privKey!=null) {
           MimeBodyPart dec = new MimeBodyPart();
           try {
               dec = toolkit.decrypt(body, new JceKeyTransRecipientId(reciCert), new JceKeyTransEnvelopedRecipient(privKey).setProvider("BC"));
           } catch (SMIMEException e) {
               e.printStackTrace();
           } catch (MessagingException e) {
               e.printStackTrace();
           }

           mailtext = dec.toString();
       }else {
           mailtext = "Entschlüsselung leider nicht möglich";
       }
        return mailtext;
    }
}