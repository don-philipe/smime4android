package tud.inf.smime4android;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.File;

/**
 * Created by don on 02.07.15.
 */
public class KeyStoreHandlerTest {

    @Test
    public void testInitKeyStore() {
        String filePath = "keystore.file";
        File ksFile = new File(filePath);
        char[] passwd = "1q2w3e4r".toCharArray();
        KeyStoreHandler.initKeyStore(ksFile, passwd);
        assertNotEquals(0, ksFile.length());
    }
}
