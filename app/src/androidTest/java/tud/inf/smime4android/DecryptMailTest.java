package tud.inf.smime4android;

import android.net.Uri;

import org.junit.Test;

/**
 * Created by don on 24.06.15.
 */
public class DecryptMailTest {

    @Test
    public void testDecrypt() {
        Uri.Builder uribuilder = new Uri.Builder();
        uribuilder.scheme("file").appendPath("mailpath");
        Uri uri = uribuilder.build();

        DecryptMail.decrypt(uri, "password".toCharArray());
    }
}
