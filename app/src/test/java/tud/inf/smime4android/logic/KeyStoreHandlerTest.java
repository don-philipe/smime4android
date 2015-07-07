package tud.inf.smime4android.logic;

import android.test.InstrumentationTestCase;

import org.junit.Test;

import java.io.File;
import java.security.Key;

import dalvik.annotation.TestTargetClass;
import tud.inf.smime4android.logic.KeyStoreHandler;

import static org.junit.Assert.*;

/**
 * Created by don on 03.07.15.
 */
public class KeyStoreHandlerTest extends InstrumentationTestCase {

    @Test
    public void testInitKeyStore() throws Exception {
        String filePath = "keystore.file";
        File ksFile = new File(filePath);
        char[] passwd = "1q2w3e4r".toCharArray();
        KeyStoreHandler ksh = new KeyStoreHandler(getInstrumentation().getContext());
        ksh.initKeyStore(ksFile, passwd);
        assertEquals(0, ksFile.length());
    }

    @Test
    public void testKeyStorePresent() {
        String filePath = "keystore.file";
        File ksFile = new File(filePath);
        char[] passwd = "1q2w3e4r".toCharArray();
        KeyStoreHandler ksh = new KeyStoreHandler(getInstrumentation().getContext());
        assertEquals(-1, ksh.keyStorePresent(ksFile, passwd));

        ksh.initKeyStore(ksFile, passwd);
        assertEquals(1, ksh.keyStorePresent(ksFile, passwd));
    }
}