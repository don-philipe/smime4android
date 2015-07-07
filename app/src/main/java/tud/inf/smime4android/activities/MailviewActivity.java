package tud.inf.smime4android.activities;

import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.FileNotFoundException;

import tud.inf.smime4android.logic.DecryptMail;
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
        String ksPath = this.getResources().getString(R.string.ks_path);
        // TODO read password from stdin ;)
        String password = "1q2w3e4r";
        if(intent.getData()!=null) {
            try {
                DecryptMail dm = new DecryptMail(this);
                content.setText(dm.decrypt(ksPath, password.toCharArray(), this.getContentResolver().openInputStream(data))
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
