package tud.inf.smime4android.logic;

import android.content.Context;
import android.test.InstrumentationTestCase;

import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
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

//    private String ksFileName = "keystore.file";
//    private char[] passwd = "1q2w3e4r".toCharArray();
//
//    public void testInitKeyStore() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        assertEquals(0, targetcontext.fileList().length);
//        ksh.initKeyStore();
//        assertEquals(this.ksFileName, targetcontext.fileList()[0]);
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testKeyStorePresent() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        File f = new File(targetcontext.getFilesDir() + "/" + this.ksFileName);
//
//        assertEquals(false, f.exists());
//        boolean result0 = false;
//        try {
//            result0 = ksh.keyStorePresent();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//        assertEquals(false, result0);
//
//        ksh.initKeyStore();
//
//        assertEquals(true, f.exists());
//        boolean result1 = false;
//        int ks_size = -1;
//        try {
//            result1 = ksh.keyStorePresent();
//            ks_size = ksh.getKeyStoreSize();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//        assertEquals(true, result1);
//        assertEquals(0, ks_size);
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testStoreAndLoad() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//
//        KeyStoreHandler ksh0 = new KeyStoreHandler(targetcontext);
//        ksh0.initKeyStore();
//
//        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
//        ksh1.initKeyStore();
//        boolean result1 = false;
//        try {
//            result1 = ksh1.keyStorePresent();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//        assertEquals(true, result1);
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testClientCertWithPrivKey() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//
//        LinkedList genCertChainPrivKeyOutput = this.generateCertChainPrivPubKey(targetcontext);
//        Certificate[] chain = (Certificate[]) genCertChainPrivKeyOutput.get(0);
//        PrivateKey privKey = (PrivateKey) genCertChainPrivKeyOutput.get(1);
//
//        assertNotNull(chain[0]);
//        assertNotNull(chain[1]);
//        assertNotNull(chain[2]);
//
//        String privKeyPasswd = "4r3e2w1q";
//        ksh.addPrivKeyAndCertificate("keyalias", chain, privKey, privKeyPasswd.toCharArray());
//
//        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
//        PrivateKey pk = null;
//        int num_aliases = 0;
//        int ks_size = 0;
//        String alias_string = "";
//        try {
//            num_aliases = ksh1.getAllAliases().size();
//            alias_string = ksh1.getAllAliases().get(0);
//            ks_size = ksh1.getKeyStoreSize();
//            pk = ksh1.getPrivKey("keyalias", privKeyPasswd.toCharArray());
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (NoSuchFieldException e) {
//            e.printStackTrace();
//        }
//        assertEquals(1, ks_size);
//        assertEquals(1, num_aliases);
//        assertEquals("keyalias", alias_string);
//        assertEquals(privKey, pk);
//
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testNewCertificate() {
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//
//        // get CA cert
//        Certificate cert = ((Certificate[]) this.generateCertChainPrivPubKey(targetcontext).getFirst())[2];
//        ksh.addCertificate("certalias", cert);
//
//        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
//        int ks_size = 0;
//        String certalias = "";
//        Certificate cert1 = null;
//        boolean alias_present = false;
//        try {
//            ks_size = ksh1.getKeyStoreSize();
//            alias_present = ksh.containsAlias("certalias");
//            certalias = ksh1.getAllAliases().get(0);
//            cert1 = ksh1.getSingleCert("certalias");
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        //} catch (NoSuchFieldException e) {
//        //    e.printStackTrace();
//        }
//        assertEquals(1, ks_size);
//        assertEquals(true, alias_present);
//        assertEquals("certalias", certalias);
//        assertEquals(cert, cert1);
//
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    public void testImportPkcs12File() {
//        byte[] pkcs12nopass = Base64.decode(
//            "MIIMvgIBAzCCDIQGCSqGSIb3DQEHAaCCDHUEggxxMIIMbTCCCS8GCSqGSIb3"
//            + "DQEHBqCCCSAwggkcAgEAMIIJFQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw"
//            + "DgQIfnlhuZRR6/YCAggAgIII6DYgeRwq5n9kzvohZ3JuK+fB+9jZ7Or6EGBA"
//            + "GDxtBfHmSNUBWJEV/I8wV1zrKKoW/CaoZfA61pyrVZRd/roaqBx/koTFoh/g"
//            + "woyyWTRV9gYTXSVqPQgCH+e2dISAa6UGO+/YOWOOwG2X3t8tS+3FduFQFLt5"
//            + "cvUP98zENdm57Aef5pKpBSZDLIAoTASfmqwszWABRh2p/wKOHcCQ9Aj2e2vs"
//            + "pls/ntIv81MqPuxHttwX8e+3dKWGFrJRztLpCD2aua8VkSsHFsPxEHkezX4O"
//            + "6/VCjMCRFGophTS4dgKKtQIhZ9i/ESlr6sGKgIpyG99ALFpNEhtTKe+T3boE"
//            + "sEkhGDquSpu4PGz2m0W5sej1DyFkKX4zIbeMDAb1y3O7aP0F+Llo9QSeGsOA"
//            + "aCwND3NUAKBMOHzwdyNQcuCGCqY8j5rrSt99A5FMs3UVW3XU6hRCx7JlzO05"
//            + "PNCkcPRSnKSNzBhIR5W0qj4PAZnQTfX+wbtUaDLIqsObX4Muh2l3gl+JmdpO"
//            + "53U7ILqN8PAPly1eT+fIrUmlMmFhvo6LbTB7B2K728wsA/5wROlud/mOQz4s"
//            + "quS288YsnVc9ExSZKodWa3Pqcdb/cgKNJYDxrR6/eBHOj+0RLK/1yTK9ghj7"
//            + "IPYHoEqQbw768WK92RjM+RFGlXASkQhR9y4weWj/388uAWMIbQ+R2Zi4nb31"
//            + "knjqRPFThysG1bsRL04/9PgysaasfS9KYOeAlLqp+Ar4gJrof5fytBuY+6wm"
//            + "/J8eEdNw7VPV1cz/4rhrd2sfJQwDEN/iZoy8rTwe7wozpwZI0lwH11BBbav+"
//            + "1AMfI79jjxhqOeo7uxE2NzUmSd05JYI7a94tcRzGQyGEKpGxYCRamzFW23qb"
//            + "vG5Hcqi7Tdd7eTxw4c60l/vQLSo38g6ST5yZrK3URLiAtpioPyjrq2jnVfie"
//            + "QLsiAHhpHF01+t+OcKv3UjwdEyBmQ34h9klwiG7iwBFXZaPXFCF2Np1TqFVG"
//            + "jjBzmB+hRddEiYwN+XGCKB2Cvgc5ZMQ8LG9jQmEKLmOjuumz1ciAVY2qtl1s"
//            + "HYSvfNsIAV/gGzHshOVF19JmGtcQt3pMtupoRh+sh8jY2/x5eIKrj2Jx6HPd"
//            + "p/6IPUr54j0xSd6j7gWuXMj/eKp/utMNuBzAhkydnhXYedvTDYIj7SyPPIHa"
//            + "qtam8rxTDWn2AOxp7OXTgPmo1GU2zW1OLL1D3MFlS+oaRMfhgNrhW+QP5ay6"
//            + "ge4QLijpnSM+p0CbFAOClwzgdJV56bBVV09sDqSBXnG9MeEv5nDaH3I+GpPA"
//            + "UgDkaI4zT61kaGgk0uNMf3czy2ycoQzTx0iHDTXSdSqvUC1yFza8UG4AYaKz"
//            + "14gtSL7StvZtK0Y8oI084BINI1LgrWyrOLj7vkds4WrKhXm21BtM1GbN/pFh"
//            + "XI41h+XoD8KnEPqJ36rAgBo1uHqTNJCC7YikDE/dEvq6MkOx+Nug1YZRHEyi"
//            + "3AHry5u1HJHtxT34HXBwRXvnstuFhvU6cjc1WY1dJhu1p82TGnx7OBo/QbcM"
//            + "8MRrWmWuU5eW4jWbriGNGYfvZy+tHnGwy0bIeqrsHOG6/JwvfmYYXe64sryH"
//            + "5Qo96SZtcTJZaNFwuBY+bFUuOWm8YrT1L7Gl2Muf3pEVtNHLeYARBo1jEAym"
//            + "Cb4jw0oodZqbPKdyyzUZu69fdTJiQkMUcKDfHJEGK0Li9SvtdqJLiiJs57Tb"
//            + "YfOvn+TIuC40ssJFtmtlGCVH/0vtKLWYeW1NYAMzgI/nlhQ7W6Aroh8sZnqv"
//            + "SwxeQmRJaVLxiV6YveTKuVlCbqNVLeEtKYAujgnJtPemGCPbwZpwlBw6V+Dz"
//            + "oXveOBcUqATztWJeNv7RbU0Mk7k057+DNxXBIU+eHRGquyHQSBXxBbA+OFuu"
//            + "4SPfEAyoYed0HEaoKN9lIsBW1xTROI30MZvaJXvPdLsa8izXGPLnTGmoI+fv"
//            + "tJ644HtBCCCr3Reu82ZsTSDMxspZ9aa4ro9Oza+R5eULXDhVXedbhJBYiPPo"
//            + "J37El5lRqOgu2SEilhhVQq3ZCugsinCaY9P/RtWG4CFnH1IcIT5+/mivB48I"
//            + "2XfH6Xq6ziJdj2/r86mhEnz9sKunNvYPBDGlOvI7xucEf9AiEQoTR1xyFDbW"
//            + "ljL4BsJqgsHN02LyUzLwqMstwv+/JH1wUuXSK40Kik/N7+jEFW2C+/N8tN7l"
//            + "RPKSLaTjxVuTfdv/BH1dkV4iGFgpQrdWkWgkb+VZP9xE2mLz715eIAg13x6+"
//            + "n97tc9Hh375xZJqwr3QyYTXWpsK/vx04RThv8p0qMdqKvf3jVQWwnCnoeBv2"
//            + "L4h/uisOLY18qka/Y48ttympG+6DpmzXTwD1LycoG2SOWckCMmJhZK40+zr3"
//            + "NVmWf6iJtbLGMxI/kzTqbTaOfXc2MroertyM1rILRSpgnJFxJfai5Enspr9b"
//            + "SCwlP718jG2lQsnYlw8CuxoZAiaNy4MmC5Y3qNl3hlcggcHeLodyGkSyRsBg"
//            + "cEiKSL7JNvqr0X/nUeW28zVxkmQsWlp3KmST8agf+r+sQvw52fXNLdYznGZV"
//            + "rJrwgNOoRj0Z70MwTns3s/tCqDEsy5Sv/5dZW2uQEe7/wvmsP2WLu73Rwplg"
//            + "1dwi/Uo9lO9dkEzmoIK5wMPCDINxL1K+0Y79q0tIAEMDgaIxmtRpEh8/TEsA"
//            + "UwyEErkDsQqgGviH+ePmawJ/yehYHTRfYUgdUflwApJxRx65pDeSYkiYboMU"
//            + "8WSAQY2nh/p9hLlS4zbz9dCK2tzVyRkJgqNy/c4IpiHEx2l1iipW9vENglqx"
//            + "dYP4uqD8e3OOLjDQKizWx2t1u7GRwoEVQ3d3QzzOvsRcv7h+6vNsmYqE6phe"
//            + "wKFZLctpSn21zkyut444ij4sSr1OG68dEXLY0t0mATfTmXXy5GJBsdK/lLfk"
//            + "YTIPYYeDMle9aEicDqaKqkZUuYPnVchGp8UFMJ3M0n48OMDdDvpzBLTxxZeW"
//            + "cK5v/m3OEo3jgxy9wXfZdz//J3zXXqvX8LpMy1K9X0uCBTz6ERlawviMQhg1"
//            + "1okD5zCCAzYGCSqGSIb3DQEHAaCCAycEggMjMIIDHzCCAxsGCyqGSIb3DQEM"
//            + "CgECoIICpjCCAqIwHAYKKoZIhvcNAQwBAzAOBAj3QoojTSbZqgICCAAEggKA"
//            + "YOSp5XGdnG1pdm9CfvlAaUSHRCOyNLndoUTqteTZjHTEM9bGwNXAx4/R5H2Q"
//            + "PnPm5HB/ynVSXX0uKdW6YlbqUyAdV3eqE4X3Nl+K7ZoXmgAFnMr0tveBhT1b"
//            + "7rTi0TN4twjJzBTkKcxT8XKjvpVizUxGo+Ss5Wk8FrWLHAiC5dZvgRemtGcM"
//            + "w5S09Pwj+qXpjUhX1pB5/63qWPrjVf+Bfmlz4bWcqogGk0i7eg+OdTeWMrW0"
//            + "KR9nD1+/uNEyc4FdGtdIPnM+ax0E+vcco0ExQpTXe0xoX4JW7O71d550Wp89"
//            + "hAVPNrJA5eUbSWNsuz+38gjUJ+4XaAEhcA7HZIp6ZyxtzSJUoh7oqpRktoxu"
//            + "3cSVqVxIqAEqlNn6j0vbKfW91Od5DI5L+BIxY4xqXS7fdwipj9r6qWA8t9QU"
//            + "C2r1A+xXpZ4jEh6inHW9qlfACBBrYf8pSDakSR6yTbaA07LExw0IXz5oiQYt"
//            + "s7yx231CZlOH88bBmruLOIZsJjeg/lf63zI7Gg4F85QG3RqEJnY2pinLUTP7"
//            + "R62VErFZPc2a85r2dbFH1mSQIj/rT1IKe32zIW8xoHC4VwrPkT3bcLFAu2TH"
//            + "5k5zSI/gZUKjPDxb2dwLM4pvsj3gJ9vcFZp6BCuLkZc5rd7CyD8HK9PrBLKd"
//            + "H3Yngy4A08W4U3XUtIux95WE+5O/UEmSF7fr2vT//DwZArGUpBPq4Bikb8cv"
//            + "0wpOwUv8r0DXveeaPsxdipXlt29Ayywcs6KIidLtCaCX6/0u/XtMsGNFS+ah"
//            + "OlumTGBFpbLnagvIf0GKNhbg2lTjflACnxIj8d+QWsnrIU1uC1JRRKCnhpi2"
//            + "veeWd1m8GUb3aTFiMCMGCSqGSIb3DQEJFTEWBBS9g+Xmq/8B462FWFfaLWd/"
//            + "rlFxOTA7BgkqhkiG9w0BCRQxLh4sAEMAZQByAHQAeQBmAGkAawBhAHQAIAB1"
//            + "AHoAeQB0AGsAbwB3AG4AaQBrAGEwMTAhMAkGBSsOAwIaBQAEFKJpUOIj0OtI"
//            + "j2CPp38YIFBEqvjsBAi8G+yhJe3A/wICCAA=");
//
//        byte[]  pkcs12 = Base64.decode(
//            "MIACAQMwgAYJKoZIhvcNAQcBoIAkgAQBMAQBgAQBMAQBgAQBBgQBCQQJKoZI"
//            + "hvcNAQcBBAGgBAGABAEkBAGABAEEBAEBBAEwBAEEBAEDBAOCAzQEAQQEAQEE"
//            + "ATAEAQQEAQMEA4IDMAQBBAQBAQQBBgQBBAQBAQQBCwQBBAQBCwQLKoZIhvcN"
//            + "AQwKAQIEAQQEAQEEAaAEAQQEAQMEA4ICpQQBBAQBAQQBMAQBBAQBAwQDggKh"
//            + "BAEEBAEBBAEwBAEEBAEBBAEbBAEEBAEBBAEGBAEEBAEBBAEKBAEEBAEKBAoq"
//            + "hkiG9w0BDAEDBAEEBAEPBA8wDQQIoagiwNZPJR4CAQEEAQQEAQEEAQQEAQQE"
//            + "AQMEA4ICgAQBBAQDggKABIICgEPG0XlhMFyrs4ZWDrvEzl51ICfXd6K2ql2l"
//            + "nnxhszUbigtSj6x49VEx4PfOB9fQFeidc5L5An+nKp646NBMIY0UwXGs8BLQ"
//            + "au59jtOs987+l7QYIvl6fdGUIuLPhVSnZZDyqD+HQjU/0/ccKFHRif4tlEQq"
//            + "aErvZbFeH0pg4ijf1HfgX6gBJGRKdO+msa4qKGnZdHCSLZehyyxvxAmURetg"
//            + "yhtEl7RmedTB+4TDs7atekqxkNlD9tfwDUX6sb0IH6qbEA6P/DlVMdaD54Cl"
//            + "QDxRzOfIIjklZhv5OMFWtPK0aYPcqyxzLpw1qRAyoTVXpidkj/hpIpgCVBP/"
//            + "k5s2+WdGbLgA/4/zSrF6feRCE5llzM2IGxiHVq4oPzzngl3R+Fi5VCPDMcuW"
//            + "NRuIOzJA+RNV2NPOE/P3knThDnwiImq+rfxmvZ1u6T06s20RmWK6cxp7fTEw"
//            + "lQ9BOsv+mmyV8dr6cYJq4IlRzHdFOyEUBDwfHThyribNKKobO50xh2f93xYj"
//            + "Rn5UMOQBJIe3b7OKZt5HOIMrJSZO02IZgvImi9yQWi96PnWa419D1cAsLWvM"
//            + "xiN0HqZMbDFfxVM2BZmsxiexLhkHWKwLqfQDzRjJfmVww8fnXpWZhFXKyut9"
//            + "gMGEyCNoba4RU3QI/wHKWYaK74qtJpsucuLWBH6UcsHsCry6VZkwRxWwC0lb"
//            + "/F3Bm5UKHax5n9JHJ2amQm9zW3WJ0S5stpPObfmg5ArhbPY+pVOsTqBRlop1"
//            + "bYJLD/X8Qbs468Bwzej0FhoEU59ZxFrbjLSBsMUYrVrwD83JE9kEazMLVchc"
//            + "uCB9WT1g0hxYb7VA0BhOrWhL8F5ZH72RMCYLPI0EAQQEAQEEATEEAQQEAQEE"
//            + "AXgEAQQEAQEEATAEAQQEAQEEAVEEAQQEAQEEAQYEAQQEAQEEAQkEAQQEAQkE"
//            + "CSqGSIb3DQEJFAQBBAQBAQQBMQQBBAQBAQQBRAQBBAQBAQQBHgQBBAQBAQQB"
//            + "QgQBBAQBQgRCAEQAYQB2AGkAZAAgAEcALgAgAEgAbwBvAGsAJwBzACAAVgBl"
//            + "AHIAaQBTAGkAZwBuACwAIABJAG4AYwAuACAASQBEBAEEBAEBBAEwBAEEBAEB"
//            + "BAEjBAEEBAEBBAEGBAEEBAEBBAEJBAEEBAEJBAkqhkiG9w0BCRUEAQQEAQEE"
//            + "ATEEAQQEAQEEARYEAQQEAQEEAQQEAQQEAQEEARQEAQQEARQEFKEcMJ798oZL"
//            + "FkH0OnpbUBnrTLgWBAIAAAQCAAAEAgAABAEwBAGABAEGBAEJBAkqhkiG9w0B"
//            + "BwYEAaAEAYAEATAEAYAEAQIEAQEEAQAEATAEAYAEAQYEAQkECSqGSIb3DQEH"
//            + "AQQBMAQBGwQBBgQBCgQKKoZIhvcNAQwBBgQPMA0ECEE7euvmxxwYAgEBBAGg"
//            + "BAGABAEEBAEIBAgQIWDGlBWxnwQBBAQBCAQI2WsMhavhSCcEAQQEAQgECPol"
//            + "uHJy9bm/BAEEBAEQBBCiRxtllKXkJS2anKD2q3FHBAEEBAEIBAjKy6BRFysf"
//            + "7gQBBAQDggMwBIIDMJWRGu2ZLZild3oz7UBdpBDUVMOA6eSoWiRIfVTo4++l"
//            + "RUBm8TpmmGrVkV32PEoLkoV+reqlyWCvqqSjRzi3epQiVwPQ6PV+ccLqxDhV"
//            + "pGWDRQ5UttDBC2+u4fUQVZi2Z1i1g2tsk6SzB3MKUCrjoWKvaDUUwXo5k9Vz"
//            + "qSLWCLTZCjs3RaY+jg3NbLZYtfMDdYovhCU2jMYV9adJ8MxxmJRz+zPWAJph"
//            + "LH8hhfkKG+wJOSszqk9BqGZUa/mnZyzeQSMTEFga1ZB/kt2e8SZFWrTZEBgJ"
//            + "oszsL5MObbwMDowNurnZsnS+Mf7xi01LeG0VT1fjd6rn9BzVwuMwhoqyoCNo"
//            + "ziUqSUyLEwnGTYYpvXLxzhNiYzW8546KdoEKDkEjhfYsc4XqSjm9NYy/BW/M"
//            + "qR+aL92j8hqnkrWkrWyvocUe3mWaiqt7/oOzNZiMTcV2dgjjh9HfnjSHjFGe"
//            + "CVhnEWzV7dQIVyc/qvNzOuND8X5IyJ28xb6a/i1vScwGuo/UDgPAaMjGw28f"
//            + "siOZBShzde0Kj82y8NilfYLHHeIGRW+N/grUFWhW25mAcBReXDd5JwOqM/eF"
//            + "y+4+zBzlO84ws88T1pkSifwtMldglN0APwr4hvUH0swfiqQOWtwyeM4t+bHd"
//            + "5buAlXOkSeF5rrLzZ2/Lx+JJmI2pJ/CQx3ej3bxPlx/BmarUGAxaI4le5go4"
//            + "KNfs4GV8U+dbEHQz+yDYL+ksYNs1eb+DjI2khbl28jhoeAFKBtu2gGOL5M9M"
//            + "CIP/JDOCHimu1YZRuOTAf6WISnG/0Ri3pYZsgQ0i4cXj+WfYwYVjhKX5AcDj"
//            + "UKnc4/Cxp+TbbgZqEKRcYVb2q0kOAxkeaNo3WCm+qvUYrwAmKp4nVB+/24rK"
//            + "khHiyYJQsETxtOEyvJkVxAS01djY4amuJ4jL0sYnXIhW3Ag93eavbzksGT7W"
//            + "Fg1ywpr1x1xpXWIIuVt1k4e+g9fy7Yx7rx0IK1qCSjNwU3QPWbaef1rp0Q/X"
//            + "P9IVXYkqo1g/T3SyXqrbZLO+sDjiG4IT3z3fJJqt81sRSVT0QN1ND8l93BG4"
//            + "QKzghYw8sZ4FwKPtLky1dDcVTgQBBAQBCAQIK/85VMKWDWYEAQQEAQgECGsO"
//            + "Q85CcFwPBAEEBAEIBAhaup6ot9XnQAQBBAQCgaAEgaCeCMadSm5fkLfhErYQ"
//            + "DgePZl/rrjP9FQ3VJZ13XrjTSjTRknAbXi0DEu2tvAbmCf0sdoVNuZIZ92W0"
//            + "iyaa2/A3RHA2RLPNQz5meTi1RE2N361yR0q181dC3ztkkJ8PLyd74nCtgPUX"
//            + "0JlsvLRrdSjPBpBQ14GiM8VjqeIY7EVFy3vte6IbPzodxaviuSc70iXM4Yko"
//            + "fQq6oaSjNBFRqkHrBAEEBAEIBAjlIvOf8SnfugQBBAQBCAQIutCF3Jovvl0E"
//            + "AQQEAQgECO7jxbucdp/3BAEEBAEIBAidxK3XDLj+BwQBBAQBCAQI3m/HMbd3"
//            + "TwwEAQQEA4ICOASCAjgtoCiMfTkjpCRuMhF5gNLRBiNv+xjg6GvZftR12qiJ"
//            + "dLeCERI5bvXbh9GD6U+DjTUfhEab/37TbiI7VOFzsI/R137sYy9Tbnu7qkSx"
//            + "u0bTvyXSSmio6sMRiWIcakmDbv+TDWR/xgtj7+7C6p+1jfUGXn/RjB3vlyjL"
//            + "Q9lFe5F84qkZjnADo66p9gor2a48fgGm/nkABIUeyzFWCiTp9v6FEzuBfeuP"
//            + "T9qoKSnCitaXRCru5qekF6L5LJHLNXLtIMSrbO0bS3hZK58FZAUVMaqawesJ"
//            + "e/sVfQip9x/aFQ6U3KlSpJkmZK4TAqp9jIfxBC8CclbuwmoXPMomiCH57ykr"
//            + "vkFHOGcxRcCxax5HySCwSyPDr8I4+6Kocty61i/1Xr4xJjb+3oyFStIpB24x"
//            + "+ALb0Mz6mUa1ls76o+iQv0VM2YFwnx+TC8KC1+O4cNOE/gKeh0ircenVX83h"
//            + "GNez8C5Ltg81g6p9HqZPc2pkwsneX2sJ4jMsjDhewV7TyyS3x3Uy3vTpZPek"
//            + "VdjYeVIcgAz8VLJOpsIjyHMB57AyT7Yj87hVVy//VODnE1T88tRXZb+D+fCg"
//            + "lj2weQ/bZtFzDX0ReiEQP6+yklGah59omeklIy9wctGV1o9GNZnGBSLvQ5NI"
//            + "61e9zmQTJD2iDjihvQA/6+edKswCjGRX6rMjRWXT5Jv436l75DVoUj09tgR9"
//            + "ytXSathCjQUL9MNXzUMtr7mgEUPETjM/kYBR7CNrsc+gWTWHYaSWuqKVBAEE"
//            + "BAEIBAh6slfZ6iqkqwQBBAQBCAQI9McJKl5a+UwEAQQEATgEOBelrmiYMay3"
//            + "q0OW2x2a8QQodYqdUs1TCUU4JhfFGFRy+g3yU1cP/9ZSI8gcI4skdPc31cFG"
//            + "grP7BAEEBAEIBAhzv/wSV+RBJQQBBAQBCAQI837ImVqqlr4EAQQEAQgECGeU"
//            + "gjULLnylBAEEBAEIBAjD3P4hlSBCvQQBBAQBCAQISP/qivIzf50EAQQEAQgE"
//            + "CKIDMX9PKxICBAEEBAOCBOgEggTocP5VVT1vWvpAV6koZupKN1btJ3C01dR6"
//            + "16g1zJ5FK5xL1PTdA0r6iAwVtgYdxQYnU8tht3bkNXdPJC1BdsC9oTkBg9Nr"
//            + "dqlF5cCzXWIezcR3ObjGLpXu49SAHvChH4emT5rytv81MYxZ7bGmlQfp8BNa"
//            + "0cMZz05A56LXw//WWDEzZcbKSk4tCsfMXBdGk/ngs7aILZ4FGM620PBPtD92"
//            + "pz2Ui/tUZqtQ0WKdLzwga1E/rl02a/x78/OdlVRNeaIYWJWLmLavX98w0PhY"
//            + "ha3Tbj/fqq+H3ua6Vv2Ff4VeXazkXpp4tTiqUxhc6aAGiRYckwZaP7OPSbos"
//            + "RKFlRLVofSGu1IVSKO+7faxV4IrVaAAzqRwLGkpJZLV7NkzkU1BwgvsAZAI4"
//            + "WClPDF228ygbhLwrSN2NK0s+5bKhTCNAR/LCUf3k7uip3ZSe18IwEkUMWiaZ"
//            + "ayktcTYn2ZjmfIfV7wIxHgWPkP1DeB+RMS7VZe9zEgJKOA16L+9SNBwJSSs9"
//            + "5Sb1+nmhquZmnAltsXMgwOrR12JLIgdfyyqGcNq997U0/KuHybqBVDVu0Fyr"
//            + "6O+q5oRmQZq6rju7h+Hb/ZUqRxRoTTSPjGD4Cu9vUqkoNVgwYOT+88FIMYun"
//            + "g9eChhio2kwPYwU/9BNGGzh+hAvAKcUpO016mGLImYin+FpQxodJXfpNCFpG"
//            + "4v4HhIwKh71OOfL6ocM/518dYwuU4Ds2/JrDhYYFsn+KprLftjrnTBnSsfYS"
//            + "t68b+Xr16qv9r6sseEkXbsaNbrGiZAhfHEVBOxQ4lchHrMp4zpduxG4crmpc"
//            + "+Jy4SadvS0uaJvADgI03DpsDYffUdriECUqAfOg/Hr7HHyr6Q9XMo1GfIarz"
//            + "eUHBgi1Ny0nDTWkdb7I3bIajG+Unr3KfK6dZz5Lb3g5NeclU5zintB1045Jr"
//            + "j9fvGGk0/2lG0n17QViBiOzGs2poTlhn7YxmiskwlkRKVafxPZNPxKILpN9s"
//            + "YaWGz93qER/pGMJarGJxu8sFi3+yt6FZ4pVPkvKE8JZMEPBBrmH41batS3sw"
//            + "sfnJ5CicAkwd8bluQpoc6qQd81HdNpS6u7djaRSDwPtYnZWu/8Hhj4DXisje"
//            + "FJBAjQdn2nK4MV7WKVwr+mNcVgOdc5IuOZbRLOfc3Sff6kYVuQFfcCGgAFpd"
//            + "nbprF/FnYXR/rghWE7fT1gfzSMNv+z5UjZ5Rtg1S/IQfUM/P7t0UqQ01/w58"
//            + "bTlMGihTxHiJ4Qf3o5GUzNmAyryLvID+nOFqxpr5es6kqSN4GPRHsmUIpB9t"
//            + "f9Nw952vhsXI9uVkhQap3JvmdAKJaIyDz6Qi7JBZvhxpghVIDh73BQTaAFP9"
//            + "5GUcPbYOYJzKaU5MeYEsorGoanSqPDeKDeZxjxJD4xFsqJCoutyssqIxnXUN"
//            + "Y3Uojbz26IJOhqIBLaUn6QVFX79buWYjJ5ZkDS7D8kq6DZeqZclt5711AO5U"
//            + "uz/eDSrx3d4iVHR+kSeopxFKsrK+KCH3CbBUMIFGX/GE9WPhDWCtjjNKEe8W"
//            + "PinQtxvv8MlqGXtv3v7ObJ2BmfIfLD0rh3EB5WuRNKL7Ssxaq14KZGEBvc7G"
//            + "Fx7jXLOW6ZV3SH+C3deJGlKM2kVhDdIVjjODvQzD8qw8a/ZKqDO5hGGKUTGD"
//            + "Psdd7O/k/Wfn+XdE+YuKIhcEAQQEAQgECJJCZNJdIshRBAEEBAEIBAiGGrlG"
//            + "HlKwrAQBBAQBCAQIkdvKinJYjJcEAQQEAUAEQBGiIgN/s1bvPQr+p1aQNh/X"
//            + "UQFmay6Vm5HIvPhoNrX86gmMjr6/sg28/WCRtSfyuYjwQkK91n7MwFLOBaU3"
//            + "RrsEAQQEAQgECLRqESFR50+zBAEEBAEIBAguqbAEWMTiPwQBBAQBGAQYKzUv"
//            + "EetQEAe3cXEGlSsY4a/MNTbzu1WbBAEEBAEIBAiVpOv1dOWZ1AQCAAAEAgAA"
//            + "BAIAAAQCAAAEAgAABAIAAAAAAAAAADA1MCEwCQYFKw4DAhoFAAQUvMkeVqe6"
//            + "D4UmMHGEQwcb8O7ZwhgEEGiX9DeqtRwQnVi+iY/6Re8AAA==");
//
//        char[] pkcs12passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
//        char[] privkeypasswd = null;
//
//        Context targetcontext = getInstrumentation().getTargetContext();
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh = new KeyStoreHandler(targetcontext);
//        ksh.initKeyStore();
//
//        int numentries = 0;
//        boolean containsalias = false;
//        FileInputStream fileInputStream = null;
//        try {
//            fileInputStream = new FileInputStream("");
//            fileInputStream.read(pkcs12nopass);
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        /*ByteArrayInputStream bais = new ByteArrayInputStream(pkcs12nopass);
//        FileInputStream fis = this.getFis(bais);*/
//        try {
//            ksh.importPkcs12File(fileInputStream, "".toCharArray(), privkeypasswd);
//            numentries = ksh.getKeyStoreSize();
//            containsalias = ksh.containsAlias("Certyfikat uzytkownika");
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//        assertEquals(1, numentries);
//        assertEquals(true, containsalias);
//
//        targetcontext.deleteFile(this.ksFileName);
//        KeyStoreHandler ksh1 = new KeyStoreHandler(targetcontext);
//        ksh1.initKeyStore();
//
//        numentries = 0;
//        containsalias = false;
//        try {
//            fileInputStream = new FileInputStream("");
//            fileInputStream.read(pkcs12);
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        try {
//            ksh1.importPkcs12File(fileInputStream, pkcs12passwd, privkeypasswd);
//            numentries = ksh1.getKeyStoreSize();
//            containsalias = ksh1.containsAlias("VeriSign Class 1 CA Individual Subscriber-Persona Not Validated - VeriSign, Inc.");
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableKeyException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//        assertEquals(3, numentries);
//        assertEquals(true, containsalias);
//
//        targetcontext.deleteFile(this.ksFileName);
//    }
//
//    /**
//     *
//     * @return a list with 3 objects, the first is the certificate chain,
//     * the second is the private key of the client certificate,
//     * third the public key of the client
//     */
//    public static LinkedList<Object> generateCertChainPrivPubKey(Context targetcontext) {
//        String provider = targetcontext.getResources().getString(R.string.ks_provider);
//
//        // personal keys
//        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
//            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
//            new BigInteger("11", 16));
//        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
//            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
//            new BigInteger("11", 16),
//            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
//            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
//            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
//            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
//            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
//            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));
//
//        // intermediate keys.
//        RSAPublicKeySpec intPubKeySpec = new RSAPublicKeySpec(
//            new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
//            new BigInteger("ffff", 16));
//        RSAPrivateCrtKeySpec intPrivKeySpec = new RSAPrivateCrtKeySpec(
//            new BigInteger("8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69", 16),
//            new BigInteger("ffff", 16),
//            new BigInteger("7deb1b194a85bcfd29cf871411468adbc987650903e3bacc8338c449ca7b32efd39ffc33bc84412fcd7df18d23ce9d7c25ea910b1ae9985373e0273b4dca7f2e0db3b7314056ac67fd277f8f89cf2fd73c34c6ca69f9ba477143d2b0e2445548aa0b4a8473095182631da46844c356f5e5c7522eb54b5a33f11d730ead9c0cff", 16),
//            new BigInteger("ef4cede573cea47f83699b814de4302edb60eefe426c52e17bd7870ec7c6b7a24fe55282ebb73775f369157726fcfb988def2b40350bdca9e5b418340288f649", 16),
//            new BigInteger("97c7737d1b9a0088c3c7b528539247fd2a1593e7e01cef18848755be82f4a45aa093276cb0cbf118cb41117540a78f3fc471ba5d69f0042274defc9161265721", 16),
//            new BigInteger("6c641094e24d172728b8da3c2777e69adfd0839085be7e38c7c4a2dd00b1ae969f2ec9d23e7e37090fcd449a40af0ed463fe1c612d6810d6b4f58b7bfa31eb5f", 16),
//            new BigInteger("70b7123e8e69dfa76feb1236d0a686144b00e9232ed52b73847e74ef3af71fb45ccb24261f40d27f98101e230cf27b977a5d5f1f15f6cf48d5cb1da2a3a3b87f", 16),
//            new BigInteger("e38f5750d97e270996a286df2e653fd26c242106436f5bab0f4c7a9e654ce02665d5a281f2c412456f2d1fa26586ef04a9adac9004ca7f913162cb28e13bf40d", 16));
//        // ca keys
//        RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
//            new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
//            new BigInteger("11", 16));
//        RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
//            new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
//            new BigInteger("11", 16),
//            new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16),
//            new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16),
//            new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16),
//            new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16),
//            new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16),
//            new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16));
//
//        // set up the keys
//        KeyFactory fact = null;
//        PrivateKey caPrivKey = null;
//        PublicKey caPubKey = null;
//        PrivateKey intPrivKey = null;
//        PublicKey intPubKey = null;
//        PrivateKey privKey = null;
//        PublicKey pubKey = null;
//        try {
//            fact = KeyFactory.getInstance("RSA", provider);
//            caPrivKey = fact.generatePrivate(caPrivKeySpec);
//            caPubKey = fact.generatePublic(caPubKeySpec);
//            intPrivKey = fact.generatePrivate(intPrivKeySpec);
//            intPubKey = fact.generatePublic(intPubKeySpec);
//            privKey = fact.generatePrivate(privKeySpec);
//            pubKey = fact.generatePublic(pubKeySpec);
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//        assertNotNull(privKey);
//        assertNotNull(pubKey);
//        assertNotNull(intPrivKey);
//        assertNotNull(intPubKey);
//
//        Certificate[] chain = new Certificate[3];
//        try {
//            String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
//            String subject0 = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
//            chain[2] = KeyStoreUtil.createMasterCert(caPubKey, caPrivKey, issuer, subject0, provider);
//            String[] issuedTo = {"AU", "The Legion of the Bouncy Castle", "Bouncy Intermediate Certificate", "feedback-crypto@bouncycastle.org"};
//            chain[1] = KeyStoreUtil.createIntermediateCert(intPubKey, caPrivKey, (X509Certificate) chain[2], issuedTo, provider);
//            String[] signer = issuedTo;
//            String[] subject1 = {"AU", "The Legion of the Bouncy Castle", "Melbourne", "Eric H. Echidna", "feedback-crypto@bouncycastle.org"};
//            chain[0] = KeyStoreUtil.createCert(pubKey, intPrivKey, intPubKey, signer, subject1, provider);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        LinkedList<Object> output = new LinkedList<Object>();
//        output.add(chain);
//        output.add(privKey);
//        output.add(pubKey);
//        return output;
//    }
}