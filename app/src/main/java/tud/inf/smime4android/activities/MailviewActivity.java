package tud.inf.smime4android.activities;

import android.content.Context;
import android.content.Intent;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import tud.inf.smime4android.logic.DecryptMail;
import tud.inf.smime4android.R;


public class MailviewActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_s4);

        // Get the intent that started this activity
        Intent intent = getIntent();
        Uri text = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        Uri data = Uri.parse(intent.getData().toString());
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
        String ksPath = this.getResources().getString(R.string.ks_path);
        // TODO read password from stdin ;)
        String password = "1q2w3e4r";
        if(intent.getData()!=null) {
            //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);

            String plaintext;
            try {
                plaintext = readTextFromUri(this, intent.getData(), "base64");
                DecryptMail dm = new DecryptMail(this);
                content.setText(plaintext);
            } catch (IOException e) {
                e.printStackTrace();
            }
/*
            try {
                DecryptMail dm = new DecryptMail(this);

//                Uri k9Uri = Uri.parse("content://com.fsck.k9.messageprovider/inbox_messages/");
//                this.getIntent().setAction("READ_MESSAGES");
//                Cursor curSt = this.getContentResolver().query(k9Uri, null, null, null, null);
//                curSt.moveToFirst();
//                String preview = curSt.getString(curSt.getColumnIndex("preview"));

                Cursor cursor = this.getContentResolver().query(data, null, null, null, null);
                cursor.moveToFirst();
                String id = cursor.getString(cursor.getColumnIndex("_id"));
                AssetFileDescriptor afd = this.getContentResolver().openAssetFileDescriptor(data, "r");
                content.setText(dm.decrypt(ksPath, password.toCharArray(), afd.createInputStream())//this.getContentResolver().openInputStream(data))
                        + "\nType:" + type
                        + "\nIntent:" + intent.toString()
                        + "\n" + intent.getData().toString());
                cursor.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
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

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public static String readTextFromUri(Context context, Uri outputUri, String charset)
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
       /* if (charset != null) {
            try {
                plaintext = new String(decryptedMessage, charset);
            } catch (UnsupportedEncodingException e) {
                // if we can't decode properly, just fall back to utf-8
                plaintext = new String(decryptedMessage);
            }
        } else {
            plaintext = new String(decryptedMessage);
        }*/
        plaintext = Base64.encodeToString(decryptedMessage, Base64.DEFAULT);

        return plaintext;

    }
}
