package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.LinkedList;

import tud.inf.smime4android.R;


/**
 * Created by don on 03.07.15.
 */
public class KeyStoreHandlerTest extends InstrumentationTestCase {

    private String ksFileName = "keystore.file";
    private char[] passwd = "1q2w3e4r".toCharArray();

    public void testInitKeyStore() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        assertEquals(0, targetcontext.fileList().length);
        ksh.initKeyStore();
        assertEquals(this.ksFileName, targetcontext.fileList()[0]);
        targetcontext.deleteFile(this.ksFileName);
    }

    public void testKeyStorePresent() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        File f = new File(targetcontext.getFilesDir() + "/" + this.ksFileName);

        assertEquals(false, f.exists());
        boolean result0 = false;
        try {
            result0 = ksh.keyStorePresent();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        assertEquals(false, result0);

        ksh.initKeyStore();

        assertEquals(true, f.exists());
        boolean result1 = false;
        int ks_size = -1;
        try {
            result1 = ksh.keyStorePresent();
            ks_size = ksh.getKeyStoreSize();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        assertEquals(true, result1);
        assertEquals(0, ks_size);
        targetcontext.deleteFile(this.ksFileName);
    }

    public void testStoreAndLoad() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(this.ksFileName);

        KeyStoreHandler ksh0 = new KeyStoreHandler(targetcontext);
        ksh0.initKeyStore();

        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
        ksh1.initKeyStore();
        boolean result1 = false;
        try {
            result1 = ksh1.keyStorePresent();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        assertEquals(true, result1);
        targetcontext.deleteFile(this.ksFileName);
    }

    public void testClientCertWithPrivKey() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();

        LinkedList genCertChainPrivKeyOutput = this.generateCertChainPrivPubKey(targetcontext);
        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
        PrivateKey privKey = (PrivateKey) genCertChainPrivKeyOutput.get(1);

        assertNotNull(chain[0]);
        assertNotNull(chain[1]);
        assertNotNull(chain[2]);

        String privKeyPasswd = "4r3e2w1q";
        ksh.addPrivKeyAndCertificate("keyalias", chain, privKey, privKeyPasswd.toCharArray());

        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
        PrivateKey pk = null;
        int num_aliases = 0;
        int ks_size = 0;
        String alias_string = "";
        try {
            num_aliases = ksh1.getAllAliases().size();
            alias_string = ksh1.getAllAliases().get(0);
            ks_size = ksh1.getKeyStoreSize();
            pk = ksh1.getPrivKey("keyalias", privKeyPasswd.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        assertEquals(1, ks_size);
        assertEquals(1, num_aliases);
        assertEquals("keyalias", alias_string);
        assertEquals(privKey, pk);

        targetcontext.deleteFile(this.ksFileName);
    }

    public void testNewCertificate() {
        Context targetcontext = getInstrumentation().getTargetContext();
        targetcontext.deleteFile(this.ksFileName);
        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
        ksh.initKeyStore();

        // get CA cert
        Certificate cert = ((Certificate[]) this.generateCertChainPrivPubKey(targetcontext).getFirst())[2];
        ksh.addCertificate("certalias", cert);

        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
        int ks_size = 0;
        String certalias = "";
        Certificate cert1 = null;
        boolean alias_present = false;
        try {
            ks_size = ksh1.getKeyStoreSize();
            alias_present = ksh.containsAlias("certalias");
            //certalias = ksh1.getAllAliases().get(0);
            cert1 = ksh1.getSingleCert("certalias");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        //} catch (NoSuchFieldException e) {
        //    e.printStackTrace();
        }
        assertEquals(1, ks_size);
        assertEquals(true, alias_present);
        //assertEquals("certalias", certalias);
        assertEquals(cert, cert1);

        targetcontext.deleteFile(this.ksFileName);
    }

    /**
     *
     * @return a list with 3 objects, the first is the certificate chain,
     * the second is the private key of the client certificate,
     * third the public key of the client
     */
    public static LinkedList<Object> generateCertChainPrivPubKey(Context targetcontext) {
        String provider = targetcontext.getResources().getString(R.string.ks_provider);

        // personal keys
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));
        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        // intermediate keys.
        RSAPublicKeySpec intPubKeySpec = new RSAPublicKeySpec(
            new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
            new BigInteger("ffff", 16));
        RSAPrivateCrtKeySpec intPrivKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
            new BigInteger("ffff", 16),
            new BigInteger("7deb1b194a85bcfd29cf871411468adbc987650903e3bacc8338c449ca7b32efd39ffc33bc84412fcd7df18d23ce9d7c25ea910b1ae9985373e0273b4dca7f2e0db3b7314056ac67fd277f8f89cf2fd73c34c6ca69f9ba477143d2b0e2445548aa0b4a8473095182631da46844c356f5e5c7522eb54b5a33f11d730ead9c0cff", 16),
            new BigInteger("ef4cede573cea47f83699b814de4302edb60eefe426c52e17bd7870ec7c6b7a24fe55282ebb73775f369157726fcfb988def2b40350bdca9e5b418340288f649", 16),
            new BigInteger("97c7737d1b9a0088c3c7b528539247fd2a1593e7e01cef18848755be82f4a45aa093276cb0cbf118cb41117540a78f3fc471ba5d69f0042274defc9161265721", 16),
            new BigInteger("6c641094e24d172728b8da3c2777e69adfd0839085be7e38c7c4a2dd00b1ae969f2ec9d23e7e37090fcd449a40af0ed463fe1c612d6810d6b4f58b7bfa31eb5f", 16),
            new BigInteger("70b7123e8e69dfa76feb1236d0a686144b00e9232ed52b73847e74ef3af71fb45ccb24261f40d27f98101e230cf27b977a5d5f1f15f6cf48d5cb1da2a3a3b87f", 16),
            new BigInteger("e38f5750d97e270996a286df2e653fd26c242106436f5bab0f4c7a9e654ce02665d5a281f2c412456f2d1fa26586ef04a9adac9004ca7f913162cb28e13bf40d", 16));
        // ca keys
        RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
            new BigInteger("11", 16));
        RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
            new BigInteger("11", 16),
            new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16),
            new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16),
            new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16),
            new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16),
            new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16),
            new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16));

        // set up the keys
        KeyFactory fact = null;
        PrivateKey caPrivKey = null;
        PublicKey caPubKey = null;
        PrivateKey intPrivKey = null;
        PublicKey intPubKey = null;
        PrivateKey privKey = null;
        PublicKey pubKey = null;
        try {
            fact = KeyFactory.getInstance("RSA", provider);
            caPrivKey = fact.generatePrivate(caPrivKeySpec);
            caPubKey = fact.generatePublic(caPubKeySpec);
            intPrivKey = fact.generatePrivate(intPrivKeySpec);
            intPubKey = fact.generatePublic(intPubKeySpec);
            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        assertNotNull(privKey);
        assertNotNull(pubKey);
        assertNotNull(intPrivKey);
        assertNotNull(intPubKey);

        Certificate[] chain = new Certificate[3];
        try {
            String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
            String subject0 = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
            chain[2] = KeyStoreUtil.createMasterCert(caPubKey, caPrivKey, issuer, subject0, provider);
            String[] issuedTo = {"AU", "The Legion of the Bouncy Castle", "Bouncy Intermediate Certificate", "feedback-crypto@bouncycastle.org"};
            chain[1] = KeyStoreUtil.createIntermediateCert(intPubKey, caPrivKey, (X509Certificate) chain[2], issuedTo, provider);
            String[] signer = issuedTo;
            String[] subject1 = {"AU", "The Legion of the Bouncy Castle", "Melbourne", "Eric H. Echidna", "feedback-crypto@bouncycastle.org"};
            chain[0] = KeyStoreUtil.createCert(pubKey, intPrivKey, intPubKey, signer, subject1, provider);
        } catch (Exception e) {
            e.printStackTrace();
        }

        LinkedList<Object> output = new LinkedList<Object>();
        output.add(chain);
        output.add(privKey);
        output.add(pubKey);
        return output;
    }
}