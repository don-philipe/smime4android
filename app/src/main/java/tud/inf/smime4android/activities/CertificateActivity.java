package tud.inf.smime4android.activities;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.TextView;

import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import tud.inf.smime4android.R;
import tud.inf.smime4android.logic.DecryptMail;
import tud.inf.smime4android.logic.StableArrayAdapter;


public class CertificateActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Intent intent = getIntent();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_certificate);

        String[] values = new String[] { "Marcos Zertifikat", "Dons Zertifikat", "Roegnaraks Zertifikat" };
        if(intent.getData()!=null) {
            //DecryptVerifyResult result = intent.getParcelableExtra(EXTRA_METADATA);



            String cert;
            try {
                cert = readTextFromUri(this, intent.getData());


//                android.net.Uri auri = intent.getData();
//                URI juri = new java.net.URI(URLEncoder.encode(auri.toString(), "UTF-8"));
//                File file = new File(intent.getData().getPath());
//                loadX509CertificateFromFile(new FileInputStream()this.getContentResolver().openInputStream(intent.getData()));

//                cert = loadX509CertificateFromFile(getFIS(this,intent.getData())).getSigAlgName();

                Collection<X509Certificate> x509certs = loadX509CertificateFromFile(getFIS(this,intent.getData()));
                //TODO import cert to keystore

//                cert = x509cert.getType()+"\n"+x509cert.getNotAfter();
                TextView tv = (TextView)findViewById(R.id.certificate);
                String certs = "";
                for(X509Certificate x: x509certs){
                    certs+=x.toString()+"\n\n";
                }
                tv.setText(certs);

                values[1] = cert;
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


        final ArrayList<String> list = new ArrayList<String>();
        for (int i = 0; i < values.length; ++i) {
            list.add(values[i]);
        }

        final ListView listView = (ListView) findViewById(R.id.certificates_listView);
        final StableArrayAdapter adapter = new StableArrayAdapter(this, list);
        listView.setAdapter(adapter);

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                final String item = (String) parent.getItemAtPosition(position);
                view.animate().setDuration(500).alpha(0)
                        .withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                list.remove(item);
                                adapter.notifyDataSetChanged();
                                view.setAlpha(1);
                            }
                        });
            }

        });

}

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        //getMenuInflater().inflate(R.menu.menu_certificate, menu);
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
        plaintext = Base64.encodeToString(decryptedMessage, Base64.DEFAULT);
        return plaintext;

    }

    public static FileInputStream getFIS(Context context, Uri uri) throws FileNotFoundException {
//        FileInputStream fis = context.openFileInput(uri.toString());
        return (FileInputStream)context.getContentResolver().openInputStream(uri);
//        return fis;
    }


    /**
     * Loads a X.509 certificate from the given file.
     *
     * @param x509CertificateFile
     *            the X.509 certificate file to load
     *
     * @throws IOException
     *             <ul>
     *             <li>if the given file does not exist</li>
     *             <li>if the given file is cannot be read</li>
     *             </ul>
     * @throws CertificateNotYetValidException
     *             if the certificate is not yet valid
     * @throws CertificateExpiredException
     *             if the certificate is not valid anymore
     * @throws CertificateException
     *             <ul>
     *             <li>if the given file is not a certificate file</li>
     *             <li>if the certificate contained in the given file is not a X.509 certificate</li>
     *             </ul>
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
            certificateFactory = CertificateFactory.getInstance("X.509",BouncyCastleProvider.PROVIDER_NAME);
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
        for(Certificate c: certificates){
            try{
                ((X509Certificate)c).checkValidity();

                x509certs.add((X509Certificate) c);
            }catch (CertificateExpiredException e){
               //ignore
            }catch(CertificateNotYetValidException e){
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
}
