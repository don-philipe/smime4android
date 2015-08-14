package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedList;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

/**
 * Created by don on 28.07.15.
 */
public class CryptMailTest extends InstrumentationTestCase {

    private String ksFileName = "keystore.file";
    private char[] ksPasswd = "1q2w3e4r".toCharArray();

    public void testDecrypt() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail dm = new CryptMail(targetcontext);
        String ciphertext = "MIAGCSqGSIb3DQEHA6CAMIACAQAxggFOMIIBSgIBADCBsjCBrDELMAkGA1UEBhMCQVQxEDAOBgNV" +
                            "BAgTB0F1c3RyaWExDzANBgNVBAcTBlZpZW5uYTEaMBgGA1UEChMRVGlhbmkgU3Bpcml0IEdtYkgx" +
                            "GTAXBgNVBAsTEERlbW8gRW52aXJvbm1lbnQxEDAOBgNVBAMTB1Rlc3QgQ0ExMTAvBgkqhkiG9w0B" +
                            "CQEWIm1hc3NpbWlsaWFuby5tYXNpQHRpYW5pLXNwaXJpdC5jb20CAQkwDQYJKoZIhvcNAQEBBQAE" +
                            "gYCsQAqbQQiRBnvrva4gJGG4ES/9EzpSxTNdM2RRT9XnE+efUCO8e6dyyRWbBZo9UCFr7ZV8/uCm" +
                            "GTCX1ZGvsdP1nDHOnPKxDWasl6bzu0DtcXp5gYsxp9tXMmEh0pISSaeWctjjd7cz60vjsHg7y2j5" +
                            "bArDfqBtnu4sJLbw/+C+hjCABgkqhkiG9w0BBwEwHQYJYIZIAWUDBAECBBDJDeXO+Imz/4Ejw8dC" +
                            "u7e0oIAEggHABb6EdlbZjFEQmw2Gc4k3uAvljBZX3munp4KE316Whb/thgJ014ntD5vGEZl5r2hD" +
                            "byvlrvDVQPAlq7s5K78KyGxzfcbzw3CK44TgH9Lmnf8cnWnaim6pspy9YbnnG4r1RW6LSqMFIMbO" +
                            "jrPuK0EKBaD5nuw1bFPo348841cltUqS/Tj3XpN9Cu5S2l7REcWWi7KP8qCOBlW/3D3WuW4TdOBg" +
                            "p3gL8qbpbinThexnaCaEdipjfA1dDplxTxJND9KS9WHRzWzrAW0l7iJ4MWfVluCqUOQodOz22jrw" +
                            "2OA462NjZv92/vJ6MZYlFhYZrRdD6qyM6cLMK3AbOuCbxJSQ8E+A0xbgDjDg86viOSvzVuoLC0R4" +
                            "C3IABR8EuHhz+1zBiFMYDIBNUqB7xXdROCo15LKSQqcPwvIjmcCxD86RxpR0xh2hnDC1Yf28th4W" +
                            "9yzZ0xOm1z+yhkztAqkPlXewI5t5hFwULGsLHyZdCmjwL8ehuszkzFxubrbJzmF/kUhQD7ZyZSIZ" +
                            "KvqfL/jcchyMMxNaGervpQEyzDZMiR21CJpZvFMTsQJwfVifskJlw2JRwgeWfeoSJYOzm0O8OrR0" +
                            "bQAAAAAAAAAAAAA=";

        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
        PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());

        String plaintext = dm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), ciphertext);
        assertEquals("hello world!", plaintext);

        targetcontext.deleteFile(this.ksFileName);
    }

    public void testDecrypt2() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail cm = new CryptMail(targetcontext);
        String ciphertext = "MIAGCSqGSIb3DQEHA6CAMIACAQAxggGuMIIBqgIBADCBkTCBhTELMAkGA1UEBhMCREUxKDAm"+
                            "BgNVBAoTH1RlY2huaXNjaGUgVW5pdmVyc2l0YWV0IERyZXNkZW4xDDAKBgNVBAsTA1pJSDEc"+
                            "MBoGA1UEAxMTVFUgRHJlc2RlbiBDQSAtIEcwMjEgMB4GCSqGSIb3DQEJARYRcGtpQHR1LWRy"+
                            "ZXNkZW4uZGUCBxkFduW1IpMwDQYJKoZIhvcNAQEBBQAEggEAMWlTpvupD29t8Od7ZoGHGqk8"+
                            "rmgmQPHbOHO0sUGGx6D2S9ab2OtuZLOoeUjeH/rV5KiPPm9qobKJQC+zR/5Dr3qETihIo80p"+
                            "2fUituGyvPzbc7tAcUHtFdEW7zyVifrUKVK4EHzR+5giALyV0kr/5rgoVF1js/4eGDGjweGe"+
                            "F3fzfAy530v+zFrxIV50qUkQQznu8B/Nj/tp0yox5tXdw/Hm5DCYNgXvgk3Hj77Nmfn8n2N5"+
                            "ZvKh+TmaCtmnHuTvTCd4K6gziS6oyfh3uHhsFNoS0HXvXjt+dAUuWAWx+v2Bv+HUyw2IlLxC"+
                            "u9AQEYvyDbyvc2n9fSI92a84VikQ+jCABgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECOrFFZ00"+
                            "KmEMoIAEeHGQ54K6g4mW4G9/ECktDSpdWvO927Z2cJCcKrp+K9QUMSEMhjcWYlZ9QfaSpwwc"+
                            "NrTEH8+P12saF2ySiuqbrd5Mt9ZIAKcZ5swYrKBE3NYoPYNQ08C3Jo6EJAve/7oR9Dh5xdK9"+
                            "/hVJ/ocDzfGkKYg30XByJNqfhwQIhaetMPv3yjoAAAAAAAAAAAAA";

        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.getFirst();
        PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.getLast();
        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());

        String plaintext = cm.decrypt(this.ksFileName, this.ksPasswd, "myalias", privKeyPasswd.toCharArray(), ciphertext);
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
