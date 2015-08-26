package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedList;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import tud.inf.smime4android.R;

/**
 * Created by don on 28.07.15.
 */
public class CryptMailTest extends InstrumentationTestCase {

    private String ksFileName = "keystore.file";
    private char[] ksPasswd = "1q2w3e4r".toCharArray();

    public void testDecrypt() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail dm = new CryptMail(targetcontext);
        byte[] testMessage = Base64.decode(
            "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
            "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
            "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
            "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
            "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
            "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
            "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
            "wMTMyLS0NCg==");

        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
        PrivateKey privkey = null;//(PrivateKey) genCertChainPrivKeyOutput.get(1);
        try {
            privkey = new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair) (
                    new PEMParser(new InputStreamReader(targetcontext.getResources().openRawResource(R.raw.key_pem)))).readObject()).getPrivate();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());

        InputStream is = new ByteArrayInputStream(testMessage);
        String plaintext = null;
        try {
            plaintext = dm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), is);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (SMIMEException e) {
            e.printStackTrace();
        }
        assertEquals("hello world!", plaintext);

        targetcontext.deleteFile(this.ksFileName);
    }

    public void testDecrypt2() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail cm = new CryptMail(targetcontext);
        byte[] testMessage = Base64.decode(
            "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
            "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
            "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
            "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
            "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
            "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
            "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
            "wMTMyLS0NCg==");

        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
        PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());

        InputStream is = new ByteArrayInputStream(testMessage);
        String plaintext = null;
        try {
            plaintext = cm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), is);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (SMIMEException e) {
            e.printStackTrace();
        }
        assertEquals("hello world!", plaintext);

        targetcontext.deleteFile(this.ksFileName);
    }

    public void testEncrypt() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail dm = new CryptMail(targetcontext);
        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
        //PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
        PublicKey pubkey = (PublicKey) genCertChainPrivKeyOutput.get(2);
        //String privKeyPasswd = "4r3e2w1q";
        //ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());
        ksh.addPubKey("myalias", pubkey, chain);

        MimeMessage mm = dm.encrypt(this.ksFileName, this.ksPasswd, "myalias", "hello world!");

        String ciphertext = "1234";
        try {
            ciphertext = mm.getContent().toString();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        assertEquals("asdf", ciphertext);
        targetcontext.deleteFile(this.ksFileName);
    }
}
