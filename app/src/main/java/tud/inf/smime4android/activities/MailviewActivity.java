package tud.inf.smime4android.activities;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import tud.inf.smime4android.logic.CryptMail;
import tud.inf.smime4android.R;


public class MailviewActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_s4);

        // Get the intent that started this activity
        Intent intent = getIntent();
        Uri data = intent.getData();
        String type = intent.getType();

        TextView sender = (TextView) findViewById(R.id.mailview_from_text);
        TextView subject = (TextView) findViewById(R.id.mailview_subject_text);
        TextView recipient = (TextView) findViewById(R.id.mailview_to_text);
        TextView content = (TextView) findViewById(R.id.mailview_content);
        //TODO prüfen:
        //if (intent.getType().equals("application/pkcs7-mime")) {
        sender.setText("Mickey Mouse");
        subject.setText("No Subject");
        recipient.setText("Goofy");
        String ksPath = this.getResources().getString(R.string.ks_filename);
        // TODO read password from stdin ;)
        String password = "1q2w3e4r";
        String alias = "keyalias";
        String privKeyPasswd = "asdf";
        if(intent.getData()!=null) {
            //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);

            String ciphertext;
            try {
                ciphertext = readTextFromUri(this, intent.getData());
                CryptMail dm = new CryptMail(this);
               // content.setText(plaintext);
                content.setText(dm.decrypt(ksPath, password.toCharArray(), alias, privKeyPasswd.toCharArray(), ciphertext));
            } catch (IOException e) {
                e.printStackTrace();
            }
/*
            try {
                DecryptMail dm = new DecryptMail(this);
                content.setText(dm.decrypt(ksPath, password.toCharArray(), this.getContentResolver().openInputStream(data))
                        + "\nType:" + type
                        + "\nIntent:" + intent.toString()
                        + "\n" + intent.getData().toString());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            */
        }
        //}
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        switch (id) {
            case R.id.action_about:
                Intent aboutIntent = new Intent(getBaseContext(), AboutActivity.class);
                startActivity(aboutIntent);
                break;
            default: break;
        }

        return super.onOptionsItemSelected(item);
    }

    public static String readTextFromUri(Context context, Uri outputUri)
            throws IOException {

        byte[] decryptedMessage;
        {
            InputStream in = context.getContentResolver().openInputStream(outputUri);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            int read;
            while ( (read = in.read(buf)) > 0) {
                out.write(buf, 0, read);
            }
            in.close();
            out.close();
            decryptedMessage = out.toByteArray();
        }

        String plaintext;
        plaintext = Base64.encodeToString(decryptedMessage,Base64.DEFAULT);
        return plaintext;

    }
}
