package tud.inf.smime4android.activities;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.TextView;

import org.bouncycastle.cms.CMSException;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;

import tud.inf.smime4android.R;
import tud.inf.smime4android.logic.CryptMail;
import tud.inf.smime4android.logic.KeyStoreHandler;
import tud.inf.smime4android.logic.NoKeyPresentException;


public class MailviewActivity extends ActionBarActivity {
    private EditText privkeypw;
    private EditText pkcs12pw;
    private EditText keystorePWEditText;
    private KeyStoreHandler ksh = null;
    private TextView content = null;
    private String keyAlias = null;
    private String keystorePW = null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mailview);


        // Get the intent that started this activity
        final Intent intent = getIntent();
        Uri data = intent.getData();
        content = (TextView) findViewById(R.id.mailview_content);
        //TODO prüfen:
        // TODO read password from stdin ;)

        FileInputStream fs = null;
        try {
            fs = getFIS(this,data);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            ksh = new KeyStoreHandler(getApplicationContext());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        if(ksh.exists()) {
            if(intent.getData()!=null) {
                //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);
                buildEnterPasswordDialog(intent, this).show();
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
        }
        else
            this.showErrorDialog("Attention", "No keystore present. You have to initialize one at first.");
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

    private AlertDialog buildEnterPasswordDialog(final Intent intent, Context context){
        final List<String> keyaliases = new ArrayList<String>();
        final AlertDialog.Builder builder = new AlertDialog.Builder(MailviewActivity.this);
        builder.setTitle("Enter Keystore password");
        LayoutInflater inflater = getLayoutInflater();
        View dialogView = inflater.inflate(R.layout.dialog_decrypt_mail, null);
        keystorePWEditText = (EditText) dialogView.findViewById(R.id.keystore_password);
//                privkeypw = (EditText) dialogView.findViewById(R.id.privatekey_password);
        builder.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                keystorePW = keystorePWEditText.getText().toString();
                try {
                    CryptMail dm = new CryptMail(getApplicationContext());
                    InputStream is = null;
                    try {
                        is = getContentResolver().openInputStream(intent.getData());
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                    //TODO: make the two passwords changeable

                    String text = "";


                        ksh.load(keystorePW.toCharArray());


                    List<String> aliases = ksh.getKeyAliases();

                    if (aliases.size() > 1){
                        //auswahl
                        Dialog aliaschooser = buildAliasChooser(dm, is, keystorePWEditText.getText().toString().toCharArray());
                        aliaschooser.show();
                    } else if (aliases.size()==1){
                        //go mit dem einzigen
                        keyAlias = ksh.getKeyAliases().get(0);
                       text = dm.decrypt(is,  keyAlias, keystorePWEditText.getText().toString().toCharArray(), "".toCharArray());
                    } 

                    //String answer = new String(decryptedMessage);

                    content.setText(text);
                } catch (MessagingException e) {
                    showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                    e.printStackTrace();
                } catch (UnrecoverableKeyException e) {
                    showErrorDialog("Error", "Either the password for the private key was wrong, or the keystore is broken.");
                    e.printStackTrace();
                } catch (CertificateException e) {
                    showErrorDialog("Error", "Cannot load a certificates from keystore.");
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    showErrorDialog("Error", "No keystore present. You have to initialize one at first.");
                    e.printStackTrace();
                } catch (CMSException e) {
                    showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                    e.printStackTrace();
                } catch (IOException e) {
                    showErrorDialog("Error", "Error while decrypting Mail: "+ e.getMessage());
                    e.printStackTrace();
                } catch (NoKeyPresentException e) {
                    showErrorDialog("Error", "No private key was found in keystore.");
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
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
        return builder.create();
    };

    public Dialog buildAliasChooser(final CryptMail dm, final InputStream is, final char[] keystorepass) {
        List<String> keyAliases = ksh.getKeyAliases();
        final String[] items = new String[keyAliases.size()];
        final ArrayAdapter<String> arrayAdapter = new ArrayAdapter<String>(
                MailviewActivity.this,
                android.R.layout.select_dialog_singlechoice);
        for (String s : keyAliases){
            arrayAdapter.add(s);
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(MailviewActivity.this);
        builder.setTitle("multipile keys found, pick one")
                .setAdapter(arrayAdapter, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
//                        keyAlias = items[which];
                        try {
                            String decryptedMessage = dm.decrypt(is,  arrayAdapter.getItem(which), keystorepass, "".toCharArray());
                            content.setText(decryptedMessage);
                        } catch (MessagingException e) {
                            e.printStackTrace();
                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        } catch (CertificateException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (UnrecoverableKeyException e) {
                            e.printStackTrace();
                        } catch (CMSException e) {
                            e.printStackTrace();
                        } catch (NoKeyPresentException e) {
                            e.printStackTrace();
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                });
        return builder.create();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_mail, menu);
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
