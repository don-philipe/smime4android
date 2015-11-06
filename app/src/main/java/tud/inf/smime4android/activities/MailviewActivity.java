package tud.inf.smime4android.activities;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.bouncycastle.cms.CMSException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import tud.inf.smime4android.logic.CryptMail;
import tud.inf.smime4android.R;


public class MailviewActivity extends ActionBarActivity {
    private EditText privkeypw;
    private EditText pkcs12pw;
    private EditText keystorepw;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mailview);


        // Get the intent that started this activity
        final Intent intent = getIntent();
        Uri data = intent.getData();
        String type = intent.getType();

        TextView sender = (TextView) findViewById(R.id.mailview_from_text);
        TextView subject = (TextView) findViewById(R.id.mailview_subject_text);
        TextView recipient = (TextView) findViewById(R.id.mailview_to_text);
        final TextView content = (TextView) findViewById(R.id.mailview_content);
        //TODO prüfen:
        //if (intent.getType().equals("application/pkcs7-mime")) {
        sender.setText("Mickey Mouse");
        subject.setText("No Subject");
        recipient.setText("Goofy");
        String ksPath = this.getResources().getString(R.string.ks_filename);
        // TODO read password from stdin ;)
        char [] password = "password".toCharArray();
        String alias = "alias";
        String privKeyPasswd = "asdf";
        FileInputStream fs = null;
        try {
            fs = getFIS(this,data);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        if(intent.getData()!=null) {
            //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);

            final AlertDialog.Builder builder = new AlertDialog.Builder(MailviewActivity.this);
            builder.setTitle("Enter Passwords");
            LayoutInflater inflater = getLayoutInflater();
            View dialogView = inflater.inflate(R.layout.dialog_decrypt_mail, null);
            keystorepw = (EditText) dialogView.findViewById(R.id.keystore_password);
            privkeypw = (EditText) dialogView.findViewById(R.id.privatekey_password);
            builder.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {

                    try {
                        CryptMail dm = new CryptMail(getApplicationContext());
                        InputStream is = null;
                        try {
                            is = getContentResolver().openInputStream(intent.getData());
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }
                        //TODO: make the two passwords changeable

                        byte[] decryptedMessage = dm.decrypt(is, "", keystorepw.getText().toString().toCharArray(), privkeypw.getText().toString().toCharArray());
                        //String answer = new String(decryptedMessage);
                        Session session = Session.getDefaultInstance(System.getProperties(), null);
                        Message msg = new MimeMessage(session, new ByteArrayInputStream(decryptedMessage));
                        String text = "";
                        Object contentObject = msg.getContent();
                        if(contentObject instanceof Multipart){
                            BodyPart clearTextPart = null;
                            BodyPart htmlTextPart = null;
                            Multipart content = (Multipart)contentObject;
                            int count = content.getCount();
                            for(int i=0; i<count; i++) {
                                BodyPart part =  content.getBodyPart(i);
                                if(part.isMimeType("text/plain")) {
                                    clearTextPart = part;
                                    break;
                                }
                                else if(part.isMimeType("text/html"))
                                    htmlTextPart = part;
                            }
                            if(clearTextPart!=null)
                                text = (String) clearTextPart.getContent();
                            else if (htmlTextPart!=null) {
                                //String html = (String) htmlTextPart.getContent();
                                //result = Jsoup.parse(html).text();
                                text = (String) htmlTextPart.getContent();
                            }
                        }
                        else if (contentObject instanceof String) // a simple text message
                            text = (String) contentObject;
                        else // not a mime message
                            throw new MessagingException();
                        content.setText(text);
                    } catch (MessagingException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                        e.printStackTrace();
                    } catch (UnrecoverableKeyException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: " + e.getMessage());
                        e.printStackTrace();
                    } catch (CertificateException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                        e.printStackTrace();
                    } catch (KeyStoreException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                        e.printStackTrace();
                    } catch (CMSException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                        e.printStackTrace();
                    } catch (IOException e) {
                        showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                        e.printStackTrace();
                    }
                }
            });
            builder.setNegativeButton(R.string.dialog_cancel, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    // User cancelled the dialog
                }
            });
            builder.setView(dialogView);
            AlertDialog dialog = builder.create();
            dialog.show();
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

    private void showErrorDialog(String title, String text) {

        AlertDialog.Builder errorDialog = new AlertDialog.Builder(MailviewActivity.this);
        errorDialog.setTitle(title);
        errorDialog.setMessage(text);
        errorDialog.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialogInterface, int i) {
            }
        });
        errorDialog.create().show();
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

    public static FileInputStream getFIS(Context context, Uri uri) throws FileNotFoundException {
        return (FileInputStream) context.getContentResolver().openInputStream(uri);
    }
}
