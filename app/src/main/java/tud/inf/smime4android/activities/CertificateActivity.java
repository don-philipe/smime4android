package tud.inf.smime4android.activities;

import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.TextView;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Text;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import tud.inf.smime4android.R;
import tud.inf.smime4android.logic.StableArrayAdapter;


public class CertificateActivity extends ActionBarActivity {

    public final ArrayList<String> list = new ArrayList<String>();
    public final ArrayList<ArrayList<X509Certificate>> certificateList = new ArrayList<ArrayList<X509Certificate>>();
    public ListView listView = null;
    public StableArrayAdapter adapter = null;

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Intent intent = getIntent();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_certificate);

        if (intent.getData() != null) {
            //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);

            String cert;
            try {
                cert = readTextFromUri(this, intent.getData());


//                android.net.Uri auri = intent.getData();
//                URI juri = new java.net.URI(URLEncoder.encode(auri.toString(), "UTF-8"));
//                File file = new File(intent.getData().getPath());
//                loadX509CertificateFromFile(new FileInputStream()this.getContentResolver().openInputStream(intent.getData()));

//                cert = loadX509CertificateFromFile(getFIS(this,intent.getData())).getSigAlgName();

                Collection<X509Certificate> x509certs = loadX509CertificateFromFile(getFIS(this, intent.getData()));
                //TODO import cert to keystore

//                cert = x509cert.getType()+"\n"+x509cert.getNotAfter();

                ArrayList<X509Certificate> temporaryCertsList = new ArrayList<X509Certificate>();
                for (X509Certificate x : x509certs) {
                    temporaryCertsList.add(x);
                }
                certificateList.add(temporaryCertsList);
                list.add(findCName(temporaryCertsList.get(temporaryCertsList.size() - 1).getSubjectDN().getName()));

//                tv.setText(certs);

            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateExpiredException e) {
                e.printStackTrace();
            } catch (CertificateNotYetValidException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }

        listView = (ListView) findViewById(R.id.certificates_listView);
        adapter = new StableArrayAdapter(this, list);
        listView.setEmptyView(findViewById(R.id.empty_listview));
        listView.setAdapter(adapter);
        registerForContextMenu(findViewById(R.id.certificates_listView));
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
            case R.id.menu_context_root: {
                onCreateDialog(getString(R.string.menu_context_root), info.position).show();
            }
            break;
            case R.id.menu_context_details: {
                ArrayList<X509Certificate> tempList = certificateList.get(info.position);
                callCertificateViewerActivity(tempList.get(tempList.size() - 1));
            }
            break;
            case R.id.menu_context_delete: {
                AlertDialog.Builder builder = new AlertDialog.Builder(CertificateActivity.this);
                builder.setMessage(R.string.dialog_delete_item_text)
                        .setTitle(R.string.dialog_delete_item_title);
                builder.setPositiveButton(R.string.dialog_ok, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        adapter.remove(adapter.getItem(info.position));
                        certificateList.remove(info.position);
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
//        FileInputStream fis = context.openFileInput(uri.toString());
        return (FileInputStream) context.getContentResolver().openInputStream(uri);
//        return fis;
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
    public static Collection<X509Certificate> loadX509CertificateFromFile(FileInputStream x509CertificateFile) throws IOException,
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

        Collection<X509Certificate> x509certs = new ArrayList<X509Certificate>();
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
