package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import tud.inf.smime4android.R;

/**
 * Created by don on 28.07.15.
 */
public class CryptMailTest extends InstrumentationTestCase {

    private final byte[] plaintext = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
        "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
        "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
        "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
        "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
        "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
        "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
        "wMTMyLS0NCg==");

    /**
     *
     */
    public void testDecryptWithPem() {
        Context targetcontext = getInstrumentation().getTargetContext();
        InputStream p7m128 = targetcontext.getResources().openRawResource(R.raw.test128message_p7m);
        InputStream p7m192 = targetcontext.getResources().openRawResource(R.raw.test192message_p7m);
        InputStream p7m256 = targetcontext.getResources().openRawResource(R.raw.test256message_p7m);
        InputStream cert128 = targetcontext.getResources().openRawResource(R.raw.cert_pem);
        InputStream cert192 = targetcontext.getResources().openRawResource(R.raw.cert_pem);
        InputStream cert256 = targetcontext.getResources().openRawResource(R.raw.cert_pem);
        InputStream key128 = targetcontext.getResources().openRawResource(R.raw.key_pem);
        InputStream key192 = targetcontext.getResources().openRawResource(R.raw.key_pem);
        InputStream key256 = targetcontext.getResources().openRawResource(R.raw.key_pem);
        CryptMail cm128 = new CryptMail(targetcontext);
        CryptMail cm192 = new CryptMail(targetcontext);
        CryptMail cm256 = new CryptMail(targetcontext);
        byte[] decrypted128 = new byte[0];
        byte[] decrypted192 = new byte[0];
        byte[] decrypted256 = new byte[0];
        try {
            decrypted128 = cm128.decrypt(p7m128, cert128, key128);
            decrypted192 = cm192.decrypt(p7m192, cert192, key192);
            decrypted256 = cm256.decrypt(p7m256, cert256, key256);
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }
        assertEquals(plaintext.length, decrypted128.length);
        assertEquals(new String(plaintext), new String(decrypted128));
        assertEquals(plaintext.length, decrypted192.length);
        assertEquals(new String(plaintext), new String(decrypted192));
        assertEquals(plaintext.length, decrypted256.length);
        assertEquals(new String(plaintext), new String(decrypted256));
    }

//    private String ksFileName = "keystore.file";
//    private char[] ksPasswd = "1q2w3e4r".toCharArray();
//    private String messageaes128 =
//            "Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\n" +
//            "Content-Transfer-Encoding: base64\n" +
//            "Content-Disposition: attachment; filename=\"smime.p7m\"\n" +
//            "Content-Description: S/MIME Encrypted Message\n\n" +
//            "MIAGCSqGSIb3DQEHA6CAMIACAQAxggFOMIIBSgIBADCBsjCBrDELMAkGA1UEBhMCQVQxEDAOBgNV" +
//            "BAgTB0F1c3RyaWExDzANBgNVBAcTBlZpZW5uYTEaMBgGA1UEChMRVGlhbmkgU3Bpcml0IEdtYkgx" +
//            "GTAXBgNVBAsTEERlbW8gRW52aXJvbm1lbnQxEDAOBgNVBAMTB1Rlc3QgQ0ExMTAvBgkqhkiG9w0B" +
//            "CQEWIm1hc3NpbWlsaWFuby5tYXNpQHRpYW5pLXNwaXJpdC5jb20CAQkwDQYJKoZIhvcNAQEBBQAE" +
//            "gYCsQAqbQQiRBnvrva4gJGG4ES/9EzpSxTNdM2RRT9XnE+efUCO8e6dyyRWbBZo9UCFr7ZV8/uCm" +
//            "GTCX1ZGvsdP1nDHOnPKxDWasl6bzu0DtcXp5gYsxp9tXMmEh0pISSaeWctjjd7cz60vjsHg7y2j5" +
//            "bArDfqBtnu4sJLbw/+C+hjCABgkqhkiG9w0BBwEwHQYJYIZIAWUDBAECBBDJDeXO+Imz/4Ejw8dC" +
//            "u7e0oIAEggHABb6EdlbZjFEQmw2Gc4k3uAvljBZX3munp4KE316Whb/thgJ014ntD5vGEZl5r2hD" +
//            "byvlrvDVQPAlq7s5K78KyGxzfcbzw3CK44TgH9Lmnf8cnWnaim6pspy9YbnnG4r1RW6LSqMFIMbO" +
//            "jrPuK0EKBaD5nuw1bFPo348841cltUqS/Tj3XpN9Cu5S2l7REcWWi7KP8qCOBlW/3D3WuW4TdOBg" +
//            "p3gL8qbpbinThexnaCaEdipjfA1dDplxTxJND9KS9WHRzWzrAW0l7iJ4MWfVluCqUOQodOz22jrw" +
//            "2OA462NjZv92/vJ6MZYlFhYZrRdD6qyM6cLMK3AbOuCbxJSQ8E+A0xbgDjDg86viOSvzVuoLC0R4" +
//            "C3IABR8EuHhz+1zBiFMYDIBNUqB7xXdROCo15LKSQqcPwvIjmcCxD86RxpR0xh2hnDC1Yf28th4W" +
//            "9yzZ0xOm1z+yhkztAqkPlXewI5t5hFwULGsLHyZdCmjwL8ehuszkzFxubrbJzmF/kUhQD7ZyZSIZ" +
//            "KvqfL/jcchyMMxNaGervpQEyzDZMiR21CJpZvFMTsQJwfVifskJlw2JRwgeWfeoSJYOzm0O8OrR0" +
//            "bQAAAAAAAAAAAAA=";
//
//    public void testDecrypt() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        CryptMail dm = new CryptMail(targetcontext);
//        byte[] testMessage = messageaes128.getBytes();
//
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
//        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
//        PrivateKey privkey = null;//(PrivateKey) genCertChainPrivKeyOutput.get(1);
//        try {
//            privkey = new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair) (
//                    new PEMParser(new InputStreamReader(targetcontext.getResources().openRawResource(R.raw.key_pem)))).readObject()).getPrivate();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        //(X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(getClass().getResourceAsStream(name));
//        String privKeyPasswd = "4r3e2w1q";
//        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());
//
//        InputStream is = new ByteArrayInputStream(testMessage);
//        String plaintext = null;
//        try {
//            plaintext = dm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), is);
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        } catch (CMSException e) {
//            e.printStackTrace();
//        } catch (NoSuchFieldException e) {
//            e.printStackTrace();
//        } catch (SMIMEException e) {
//            e.printStackTrace();
//        }
//        assertEquals("hello world!", plaintext);
//
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testDecrypt2() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        CryptMail cm = new CryptMail(targetcontext);
//        byte[] testMessage = messageaes128.getBytes();
//        getClass();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
//        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
//        PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
//        String privKeyPasswd = "4r3e2w1q";
//        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());
//
//        InputStream is = new ByteArrayInputStream(testMessage);
//        String plaintext = null;
//        try {
//            MimeMessage mm = cm.decrypt1(privKeyPasswd.toCharArray(), is);
//            plaintext = cm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), is);
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        } catch (CMSException e) {
//            e.printStackTrace();
//        } catch (NoSuchFieldException e) {
//            e.printStackTrace();
//        } catch (SMIMEException e) {
//            e.printStackTrace();
//        }
//        assertEquals("hello world!", plaintext);
//
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
////    public void testDecrypt3() {
////        SMIMEEnveloped env = new SMIMEEnveloped(message);
////        RecipientInformationStore store = env.getRecipientInfos();
////        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));
////        assertNotNull(recipInfo);
////        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));
////    }
//
//    public void testEncrypt() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        CryptMail dm = new CryptMail(targetcontext);
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
//        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
//        //PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
//        PublicKey pubkey = (PublicKey) genCertChainPrivKeyOutput.get(2);
//        //String privKeyPasswd = "4r3e2w1q";
//        //ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());
//        ksh.addPubKey("myalias", pubkey, chain);
//
//        MimeMessage mm = dm.encrypt(this.ksFileName, this.ksPasswd, "myalias", "hello world!");
//
//        String ciphertext = "1234";
//        try {
//            ciphertext = mm.getContent().toString();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        }
//        assertEquals("asdf", ciphertext);
//        targetcontext.deleteFile(this.ksFileName);
//    }
}
