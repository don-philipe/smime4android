package tud.inf.smime4android.activities;

import android.content.Intent;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.security.cert.X509Certificate;

import tud.inf.smime4android.R;

public class CertificateViewerActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_certificate_viewer);

        Intent intent = getIntent();
        String[] strings = new String[7];
        String country = null,
                org = null,
                orgunit = null,
                email = null,
                startDate = null,
                endDate = null,
                plaintext = null,
                cName = null;
        country = intent.getStringExtra("country");
        org = intent.getStringExtra("org");
        orgunit = intent.getStringExtra("orgunit");
        email = intent.getStringExtra("email");
        startDate = intent.getStringExtra("startDate");
        endDate = intent.getStringExtra("endDate");
        plaintext = intent.getStringExtra("plaintext");
        cName = intent.getStringExtra("cName");

        setTitle(cName);

        TextView startDatetv = (TextView) findViewById(R.id.certview_startDate_text);
        startDatetv.setText(startDate);
        TextView endDatetv = (TextView) findViewById(R.id.certview_endDate_text);
        endDatetv.setText(endDate);
        TextView countrytv = (TextView) findViewById(R.id.certview_country_text);
        countrytv.setText(country);
        TextView orgtv = (TextView) findViewById(R.id.certview_org_text);
        orgtv.setText(org);
        TextView orgunittv = (TextView) findViewById(R.id.certview_orgunit_text);
        orgunittv.setText(orgunit);
        TextView emailtv = (TextView) findViewById(R.id.certview_email_text);
        emailtv.setText(email);
        TextView plaintexttv = (TextView) findViewById(R.id.certview_plaintext);
        plaintexttv.setText(plaintext);
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
}
