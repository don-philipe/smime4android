package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import tud.inf.smime4android.R;


/**
 * Created by don on 03.07.15.
 */
public class KeyStoreHandlerTest extends InstrumentationTestCase {

    /**
     *
     */
    public void testLoadNStore() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(targetcontext.getResources().getString(R.string.ks_filename));
        char[] passwd = {'p', 'a', 's', 's', 'w', 'd'};

        assertEquals(false, checkFileExistence(targetcontext, ".p12"));

        try {
            KeyStoreHandler ksh = new KeyStoreHandler(targetcontext, passwd);
            ksh.storeKeyStore();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        assertEquals(true, checkFileExistence(targetcontext, ".p12"));
    }

    /**
     *
     */
    public void testImportPkcs12() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(targetcontext.getResources().getString(R.string.ks_filename));
        char[] ks_passwd = {'p', 'a', 's', 's', 'w', 'd'};

        try {
            KeyStoreHandler ksh = new KeyStoreHandler(targetcontext, ks_passwd);
            InputStream inp12 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
            char[] p12_passwd = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

            assertEquals(false, ksh.getAliases().hasMoreElements());

            ksh.importPKCS12(inp12, p12_passwd, null);
            ksh.storeKeyStore();

            assertEquals(true, ksh.getAliases().hasMoreElements());

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 
     */
    public void testGetPrivateKeyAndCert() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(targetcontext.getResources().getString(R.string.ks_filename));
        char[] ks_passwd = {'p', 'a', 's', 's', 'w', 'd'};

        try {
            KeyStoreHandler ksh = new KeyStoreHandler(targetcontext, ks_passwd);
            InputStream inp12 = targetcontext.getResources().openRawResource(R.raw.key_and_cert_p12);
            char[] p12_passwd = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

            ksh.importPKCS12(inp12, p12_passwd, null);
            ksh.storeKeyStore();

            InputStream keystream = targetcontext.getResources().openRawResource(R.raw.key_pem);
            PrivateKey exp_key = new JcaPEMKeyConverter().setProvider("BC")
                    .getKeyPair((PEMKeyPair) (new PEMParser(new InputStreamReader(keystream))).readObject()).getPrivate();
            InputStream certstream = targetcontext.getResources().openRawResource(R.raw.cert_pem);
            X509Certificate exp_cert = null;
            try {
                exp_cert = (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                        .generateCertificate(certstream);
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }

            Enumeration<String> aliases = ksh.getAliases();
            PrivateKey key = null;
            Certificate cert = null;
            while(aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                key = ksh.getPrivateKey(alias, null);
                cert = ksh.getCertificate(alias);
            }

            assertEquals(new String(exp_key.getEncoded()), new String(key.getEncoded()));
            assertEquals(new String(exp_cert.getEncoded()), new String(cert.getEncoded()));

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param context to get file directory
     * @param filename suffix of filename to be checked
     * @return whether the file exists or not
     */
    private boolean checkFileExistence(Context context, String filename) {
        String[] filelist = context.fileList();
        boolean exists = false;
        for(int i = 0; i < filelist.length; i++) {
            if(filelist[i].endsWith(filename))
                exists = true;
        }
        return exists;
    }
}