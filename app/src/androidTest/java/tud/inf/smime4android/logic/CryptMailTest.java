package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.mail.MessagingException;

import tud.inf.smime4android.R;

/**
 * Created by don on 28.07.15.
 */
public class CryptMailTest extends InstrumentationTestCase {

    String s = "MIME-Version: 1.0\r" +
            "\nContent-Type: multipart/mixed; \r" +
            "\n\tboundary=\"----=_Part_0_260396386.1352904750132\"\r" +
            "\nContent-Language: en\r" +
            "\nContent-Description: A mail following the DIRECT project specifications\r" +
            "\n\r\n------=_Part_0_260396386.1352904750132\r" +
            "\nContent-Type: text/plain; name=null; charset=us-ascii\r" +
            "\nContent-Transfer-Encoding: 7bit\r" +
            "\nContent-Disposition: inline; filename=null\r" +
            "\n\r\nCiao from vienna\r" +
            "\n------=_Part_0_260396386.1352904750132--\r\n";
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
        CryptMail cm = new CryptMail(targetcontext);
        byte[] decrypted128 = new byte[0];
        byte[] decrypted192 = new byte[0];
        byte[] decrypted256 = new byte[0];
        try {
            decrypted128 = cm.decrypt(p7m128, key128, cert128);
            decrypted192 = cm.decrypt(p7m192, key192, cert192);
            decrypted256 = cm.decrypt(p7m256, key256, cert256);
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

    /**
     *
     */
    public void testDecryptWithPkcs12() {
        Context targetcontext = getInstrumentation().getTargetContext();
        InputStream p7m128 = targetcontext.getResources().openRawResource(R.raw.test128message_p7m);
        InputStream p7m192 = targetcontext.getResources().openRawResource(R.raw.test192message_p7m);
        InputStream p7m256 = targetcontext.getResources().openRawResource(R.raw.test256message_p7m);
        InputStream p12128 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
        InputStream p12192 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
        InputStream p12256 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
        CryptMail cm = new CryptMail(targetcontext);
        char[] passwd = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        byte[] decrypted128 = new byte[0];
        byte[] decrypted192 = new byte[0];
        byte[] decrypted256 = new byte[0];
        try {
            decrypted128 = cm.decrypt(p7m128, p12128, passwd, null);
            decrypted192 = cm.decrypt(p7m192, p12192, passwd, null);
            decrypted256 = cm.decrypt(p7m256, p12256, passwd, null);
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        assertEquals(plaintext.length, decrypted128.length);
        assertEquals(new String(plaintext), new String(decrypted128));
        assertEquals(plaintext.length, decrypted192.length);
        assertEquals(new String(plaintext), new String(decrypted192));
        assertEquals(plaintext.length, decrypted256.length);
        assertEquals(new String(plaintext), new String(decrypted256));
    }

    /**
     *
     */
    public void testDecryptWithKeyStoreHandler() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(targetcontext.getResources().getString(R.string.ks_filename));
        InputStream p12 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
        char[] p12_passwd = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        char[] ks_passwd = {'p', 'a', 's', 's', 'w', 'd'};

        try {
            KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
            ksh.load(ks_passwd);
            ksh.importPKCS12(p12, p12_passwd, null);
            ksh.storeKeyStore();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        InputStream p7m128 = targetcontext.getResources().openRawResource(R.raw.test128message_p7m);
        InputStream p7m192 = targetcontext.getResources().openRawResource(R.raw.test192message_p7m);
        InputStream p7m256 = targetcontext.getResources().openRawResource(R.raw.test256message_p7m);

        CryptMail cm = new CryptMail(targetcontext);
        byte[] decrypted128 = new byte[0];
        byte[] decrypted192 = new byte[0];
        byte[] decrypted256 = new byte[0];
        try {
            decrypted128 = cm.decrypt(p7m128, "", ks_passwd, null);
            decrypted192 = cm.decrypt(p7m192, "", ks_passwd, null);
            decrypted256 = cm.decrypt(p7m256, "", ks_passwd, null);
        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoKeyPresentException e) {
            e.printStackTrace();
        }
        assertEquals(plaintext.length, decrypted128.length);
        assertEquals(new String(plaintext), new String(decrypted128));
        assertEquals(plaintext.length, decrypted192.length);
        assertEquals(new String(plaintext), new String(decrypted192));
        assertEquals(plaintext.length, decrypted256.length);
        assertEquals(new String(plaintext), new String(decrypted256));
    }
}
