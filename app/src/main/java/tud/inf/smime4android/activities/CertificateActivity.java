package tud.inf.smime4android.activities;

import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Base64;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import tud.inf.smime4android.R;
import tud.inf.smime4android.logic.KeyStoreHandler;
import tud.inf.smime4android.logic.StableArrayAdapter;


public class CertificateActivity extends ActionBarActivity {

    public final ArrayList<String> list = new ArrayList<String>();
    public final ArrayList<ArrayList<X509Certificate>> certificateList = new ArrayList<ArrayList<X509Certificate>>();
    public ListView listView = null;
    public StableArrayAdapter adapter = null;
    private KeyStoreHandler ksh = null;
    private EditText privkeypw;
    private EditText pkcs12pw;

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    protected void onCreate(Bundle savedInstanceState) {

        try {
            ksh = new KeyStoreHandler(getApplicationContext(),"".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        final Intent intent = getIntent();

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_certificate);

//        final Button bibabutzebutton = (Button) findViewById(R.id.button);
//        bibabutzebutton.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View view) {
//                Context context = getApplicationContext();
//                int duration = Toast.LENGTH_SHORT;
//                 int size = ksh.keyStoreSize();
//
//                String text = "size " + size;
//                Toast toast = Toast.makeText(context, text, duration);
//                toast.show();
//
//            }
//        });

        if (intent.getData() != null) {

            AlertDialog.Builder builder = new AlertDialog.Builder(CertificateActivity.this);
            builder.setTitle("Enter password for private Key");
            LayoutInflater inflater = getLayoutInflater();
            View dialogView = inflater.inflate(R.layout.dialog_addkeystore, null);
            pkcs12pw = (EditText) dialogView.findViewById(R.id.pkcs12_password);
            privkeypw = (EditText) dialogView.findViewById(R.id.privatekey_password);
            final Context context = this;
            builder.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    String privateKeyPassword = privkeypw.getText().toString();
                    String pkcs12Password = pkcs12pw.getText().toString();

                    InputStream is = null;
                    try {
                        is = getContentResolver().openInputStream(intent.getData());
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }

                    try {
                        try {
                            ksh.importPKCS12(is, pkcs12Password.toCharArray(), privateKeyPassword.toCharArray());
                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (UnrecoverableKeyException e) {
                        e.printStackTrace();
                    }
                    try {
                        ksh.storeKeyStore();
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    } catch (KeyStoreException e) {
                        e.printStackTrace();
                    }
                    updateList();
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

            // TODO dialog

        }
            // gief password

              listView = (ListView) findViewById(R.id.certificates_listView);
            adapter = new StableArrayAdapter(this, list);
            listView.setEmptyView(findViewById(R.id.empty_listview));
            listView.setAdapter(adapter);
            updateList();
            registerForContextMenu(findViewById(R.id.certificates_listView));
    }

    private void addCertificateToKS(Uri data, String password) {

        boolean accessToKeyPair;
        KeyPair keyPair = null;
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();

        try {
            keyPair = loadKeysFromFile(getFIS(this, data), password);
            accessToKeyPair = true;
        } catch (IOException e) {
            e.printStackTrace();
            //pw falsch
            Toast toast = Toast.makeText(getApplicationContext(), "Wrong password", Toast.LENGTH_SHORT);
            toast.show();
            accessToKeyPair = false;
        }

        if (accessToKeyPair){
            try {
                certificates = loadX509CertificateFromFile(getFIS(this, data));
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            }

            Certificate [] certArray = new Certificate[certificates.size()];

            for (int i = 0; i<certificates.size(); i++){
                certArray[i] = certificates.get(i);
            }
//            ksh.addPrivKeyAndCertificate("privkeypw", certArray, keyPair.getPrivate(), password.toCharArray());

            updateList();
            // TODO Add to list
        }
    }

    private void updateList() {
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        list.clear();

        try {
            Enumeration<String> aliases = ksh.getAliases();
            while(aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                list.add(alias);
            }

            //certificates = ksh.getAllCertificates();
        //} catch (NoSuchFieldException e) {
        //    e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        //for (int i = 0; i<certificates.size(); i++){
            //list.add( findCName(certificates.get(i).getSubjectDN().getName().toString()));
        //}
        adapter.notifyDataSetChanged();
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v,
                                    ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        AdapterView.AdapterContextMenuInfo info;
        try {
            // Casts the incoming data object into the type for AdapterView objects.
            info = (AdapterView.AdapterContextMenuInfo) menuInfo;
        } catch (ClassCastException e) {
            // If the menu object can't be cast, logs an error.
            return;
        }
        MenuInflater inflater = getMenuInflater();
        menu.setHeaderTitle(list.get(info.position));
        inflater.inflate(R.menu.menu_context_listview, menu);
    }

    @Override
    public boolean onContextItemSelected(final MenuItem item) {
        final AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
            case R.id.menu_context_details: {
//                ArrayList<X509Certificate> tempList = certificateList.get(info.position);
//                callCertificateViewerActivity(tempList.get(tempList.size() - 1));
                String alias = list.get(info.position);
                String cert = "";
//                try {
//                   cert = ksh.getSingleCert()
//                } catch (KeyStoreException e) {
//                    e.printStackTrace();
//                }

                Context context = getApplicationContext();

                int duration = Toast.LENGTH_SHORT;


                Toast toast = Toast.makeText(context, cert, duration);
                toast.show();

            }

            break;
            case R.id.menu_context_delete: {
                AlertDialog.Builder builder = new AlertDialog.Builder(CertificateActivity.this);
                builder.setMessage(R.string.dialog_delete_item_text)
                        .setTitle(R.string.dialog_delete_item_title);
                builder.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
//                      ksh.removeCertificate("privkeypw");
                        //TODO hardcoded, find out privkeypw and delete it
                        updateList();

                    }
                });
                builder.setNegativeButton(R.string.dialog_cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        // User clicked button
                    }
                });


                builder.create().show();

            }
            break;
            default:
                return super.onContextItemSelected(item);
        }
        return false;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    protected Dialog onCreateDialog(String title, int position) {
        // TODO Auto-generated method stub

                final ArrayList<X509Certificate> tempList = certificateList.get(position);
                String[] stringArray = new String[tempList.size() - 1];
                if (tempList.size() > 1) {
                    for (int i = 0; i < tempList.size() - 1; i++) {
                        stringArray[i] = findCName(tempList.get(i).getSubjectDN().toString());
                    }
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle(title);
                builder.setItems(stringArray, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int item) {
                        callCertificateViewerActivity(tempList.get(item));
                    }
                });
                builder.setPositiveButton(R.string.dialog_close, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        // User clicked OK button
                    }
                });

                return builder.create();
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
            while ((read = in.read(buf)) > 0) {
                out.write(buf, 0, read);
            }
            in.close();
            out.close();
            decryptedMessage = out.toByteArray();
        }

        String plaintext;
        plaintext = Base64.encodeToString(decryptedMessage, Base64.DEFAULT);
        return plaintext;

    }

    public static FileInputStream getFIS(Context context, Uri uri) throws FileNotFoundException {
        return (FileInputStream) context.getContentResolver().openInputStream(uri);
    }


    /**
     * Loads a X.509 certificate from the given file.
     *
     * @param x509CertificateFile the X.509 certificate file to load
     * @throws IOException                     <ul>
     *                                         <li>if the given file does not exist</li>
     *                                         <li>if the given file is cannot be read</li>
     *                                         </ul>
     * @throws CertificateNotYetValidException if the certificate is not yet valid
     * @throws CertificateExpiredException     if the certificate is not valid anymore
     * @throws CertificateException            <ul>
     *                                         <li>if the given file is not a certificate file</li>
     *                                         <li>if the certificate contained in the given file is not a X.509 certificate</li>
     *                                         </ul>
     */
    public static ArrayList<X509Certificate> loadX509CertificateFromFile(FileInputStream x509CertificateFile) throws IOException,
            CertificateNotYetValidException, CertificateExpiredException, CertificateException {


        // Check availablity and readability of the given file first
//        if (!x509CertificateFile.exists()) {
//            String message = "The given file \"" + x509CertificateFile + "\" does not exist.";
//            throw new IOException(message);
//        } else if (!x509CertificateFile.canRead()) {
//            String message = "The given file \"" + x509CertificateFile + "\" cannot be read.";
//            throw new IOException(message);
//        }

        // Since the file seems to be ok, try to make a X509 certificate from it.
        CertificateFactory certificateFactory = null;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchProviderException e) {
            // Shouldn't happen, since the BouncyCastle provider was added on class loading
            // or even before
            throw new RuntimeException("Certificate provider not found.", e);
        }

        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(x509CertificateFile);
        if (certificates.isEmpty()) {
            String message = "The given file \"" + x509CertificateFile + "\" does not contain a X.509 certificate.";
            throw new CertificateException(message);
        }
//        if (!certificate.getType().equalsIgnoreCase("x.509")) {
//            String message = "The certificate contained in the given file \"" + x509CertificateFile + "\" is not a X.509 certificate.";
//            throw new CertificateException(message);
//        }

        ArrayList<X509Certificate> x509certs = new ArrayList<X509Certificate>();
        Certificate[] certArray = new Certificate[certificates.size()];
        for (Certificate c : certificates) {
            try {
                ((X509Certificate) c).checkValidity();
                x509certs.add((X509Certificate) c);
            } catch (CertificateExpiredException e) {
                //ignore
            } catch (CertificateNotYetValidException e) {
                //ignore
            }

        }
//        X509Certificate x509Certificate = (X509Certificate) certificate;
        // Lastly checks if the certificate is (still) valid.
        // If not this throws a CertificateExpiredException or
        // CertificateNotYetValidException respectively.
//        x509Certificate.checkValidity();

        return x509certs;
    }


    public static KeyPair loadKeysFromFile(FileInputStream x509KeyFile, String password) throws IOException {
        Reader reader = new InputStreamReader(x509KeyFile);
        PEMParser pemParser = new PEMParser(reader);
        //TODO really!?

        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;
        if (object instanceof PEMEncryptedKeyPair) {
            System.out.println("Encrypted key - we will use provided password");
            kp = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
        } else {
            System.out.println("Unencrypted key - no password needed");
            kp = converter.getKeyPair((PEMKeyPair) object);
        }

        return kp;
    }

    private String findCName(String string) {
        String[] stringArray = string.split(",");
        String result = "";
        for (String s : stringArray) {
            if (s.startsWith("CN=")) {
                result = s.substring(3);
            }
        }

        return result;
    }

    private void callCertificateViewerActivity(X509Certificate certificate) {
        String country = null,
                org = null,
                orgunit = null,
                email = null,
                startDate = null,
                endDate = null,
                plaintext = null,
                cName = null;
        endDate = certificate.getNotAfter().toString();
        startDate = certificate.getNotBefore().toString();
        String[] stringArray = certificate.getSubjectDN().toString().split(",");
        for (String s : stringArray) {
            if (s.startsWith("C=")) {
                country = s.substring(2);
            }
            if (s.startsWith("O=")) {
                org = s.substring(2);
            }
            if (s.startsWith("OU=")) {
                orgunit = s.substring(3);
            }
            if (s.startsWith("E=")) {
                email = s.substring(2);
            }
        }
        cName = findCName(certificate.getSubjectDN().toString());
        plaintext = certificate.toString();
        Intent certificateIntent = new Intent(getBaseContext(), CertificateViewerActivity.class);
        certificateIntent.putExtra("country", country);
        certificateIntent.putExtra("org", org);
        certificateIntent.putExtra("orgunit", orgunit);
        certificateIntent.putExtra("email", email);
        certificateIntent.putExtra("startDate", startDate);
        certificateIntent.putExtra("endDate", endDate);
        certificateIntent.putExtra("plaintext", plaintext);
        certificateIntent.putExtra("cName", cName);
        startActivity(certificateIntent);

    }

}
