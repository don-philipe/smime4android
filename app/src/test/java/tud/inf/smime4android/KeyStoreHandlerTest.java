package tud.inf.smime4android;

import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;

/**
 * Created by don on 03.07.15.
 */
public class KeyStoreHandlerTest {

    @Test
    public void testInitKeyStore() throws Exception {
        String filePath = "keystore.file";
        File ksFile = new File(filePath);
        char[] passwd = "1q2w3e4r".toCharArray();
        KeyStoreHandler.initKeyStore(ksFile, passwd);
        assertEquals(0, ksFile.length());
    }
}