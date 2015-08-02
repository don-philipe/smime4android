package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.LinkedList;

/**
 * Created by don on 28.07.15.
 */
public class CryptMailTest extends InstrumentationTestCase {

    private String ksFileName = "keystore.file";
    private char[] ksPasswd = "1q2w3e4r".toCharArray();

    public void testDecrypt() {
        Context targetcontext = getInstrumentation().getTargetContext();
        CryptMail dm = new CryptMail(targetcontext);
        String encmail = "";

        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext, this.ksFileName, this.ksPasswd);
        ksh.initKeyStore();
        LinkedList genCertChainPrivKeyOutput = KeyStoreHandlerTest.generateCertChainPrivKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.getFirst();
        PrivateKey privkey = (PrivateKey) genCertChainPrivKeyOutput.getLast();
        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("myalias", chain, privkey, privKeyPasswd.toCharArray());

        dm.decrypt(this.ksFileName, this.ksPasswd, encmail);
        targetcontext.deleteFile(this.ksFileName);
    }
}
