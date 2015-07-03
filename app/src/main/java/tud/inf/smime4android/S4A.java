package tud.inf.smime4android;

import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


public class S4A extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_s4);

        // Get the intent that started this activity
        Intent intent = getIntent();
        Uri data = intent.getData();
        String type = intent.getType();

        //data = Uri.parse("file:///foo/bar");

        TextView sender = (TextView) findViewById(R.id.mailview_from_text);
        TextView subject = (TextView) findViewById(R.id.mailview_subject_text);
        TextView recipient = (TextView) findViewById(R.id.mailview_to_text);
        TextView content = (TextView) findViewById(R.id.mailview_content);
        //TODO prüfen:
        //if (intent.getType().equals("application/pkcs7-mime")) {
        //TODO: ask for password
        String password = "password";
        sender.setText("Mickey Mouse");
        subject.setText("No Subject");
        recipient.setText("Goofy");
        if(intent.getData()!=null) {
            try {
                FileInputStream fis = null;
                content.setText(DecryptMail.decrypt(data, password.toCharArray(), this.getContentResolver().openInputStream(data))
                        + "\nType:" + type
                        + "\nIntent:" + intent.toString()
                        + "\n" + intent.getData().toString());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
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
}
