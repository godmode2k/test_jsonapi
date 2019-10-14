/*
    Android + PHP: Custom APIs test
     - hjkim, 2019.10.10


    Usage:
    CApiTest apitest = new CApiTest();
    if (apitest != null) {
        apitest.test();
    }
 */



package com.test.apitest;

import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;

/*
{
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ...
        {
            // Android 9.0
            // [Error]
            // - "NetworkSecurityConfig: No Network Security Config specified, using platform default"
            //
            // - add: AndroidManifest.xml {
            // ...
            // <application
            //     //android:usesCleartextTraffic="true"
            //     android:networkSecurityConfig="@xml/network_security_config"
            //     ...
			// </application>
			// <uses-permission android:name="android.permission.INTERNET"></uses-permission>
			// ...
            // }
            // - creates: res/xml/network_security_config.xml {
            //     <?xml version="1.0" encoding="utf-8"?>
            //     <network-security-config>
            //     <base-config cleartextTrafficPermitted="true" />
            //     </network-security-config>
            // }

            // checks permission
            if (ContextCompat.checkSelfPermission(this,
                    Manifest.permission.INTERNET)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.INTERNET},
                        100);   // 100: my request code
            }
            else {
                Toast.makeText( this, "granted already...", Toast.LENGTH_SHORT).show();

                CApiTest apitest = new CApiTest();
                if (apitest != null) {
                    apitest.test();
                }
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        switch (requestCode) {
            case 100: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Toast.makeText( this, "granted...", Toast.LENGTH_SHORT).show();

                    CApiTest apitest = new CApiTest();
                    if (apitest != null) {
                        apitest.test();
                    }
                }
            }
        }
    }
}
*/
public class CApiTest {
    final static String TAG = "CApiTest";


    public CApiTest() {
        //
    }

    public class CALL_API extends AsyncTask<Void, Void, String> {
        @Override
        protected String doInBackground(Void... voids) {
            String result = apis();
            return result;
        }

        @Override
        protected void onPostExecute(String result) {
            super.onPostExecute(result);

            Log.d( TAG, "result = " + result);
        }
    }


    public void test() {
        CALL_API call_api = new CALL_API();

        if ( call_api != null ) {
            call_api.execute();

            call_api = null;
        }
    }




    public static PublicKey rsa_get_public_key_from_string(final String public_key) {
        PublicKey key = null;
        try {
            final byte[] encoded_key = android.util.Base64.decode(public_key, Base64.DEFAULT);

            KeyFactory fac = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509_spec = new X509EncodedKeySpec(encoded_key);
            key = fac.generatePublic(x509_spec);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }

    public static PrivateKey rsa_get_private_key_from_string(final String private_key) {
        PrivateKey key = null;
        try {
            final byte[] encoded_key = android.util.Base64.decode(private_key, Base64.DEFAULT);

            KeyFactory fac = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec(encoded_key);
            key = fac.generatePrivate(key_spec);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }
    public static String rsa_encrypt(final PublicKey public_key, final String text) {
        return rsa_encrypt(public_key, text.getBytes());
    }
    public static String rsa_encrypt(final PublicKey public_key, final byte text[]) {
        String encrypted = null;

        try {
            //Cipher cipher = Cipher.getInstance("RSA");
            //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, public_key);
            byte[] data = cipher.doFinal(text);

            //encrypted = Base64.getEncoder().encodeToString(data);
            // SDK min 19
            encrypted = android.util.Base64.encodeToString(data, Base64.DEFAULT);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return encrypted;
    }
    // decrypt
    // cf. https://stackoverflow.com/questions/26068460/decrypting-php-encrypted-data-on-android



    /*
    //! NOTE: Cipher.getInstance("RSA");
    public static String rsa_encrypt(final PublicKey public_key, final String text) {
        return rsa_encrypt(public_key, text.getBytes());
    }
    public static String rsa_encrypt(final PublicKey public_key, final byte text[]) {
        String encrypted = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, public_key);
            byte[] data = cipher.doFinal(text);

            //encrypted = Base64.getEncoder().encodeToString(data);
            // SDK min 19
            encrypted = android.util.Base64.encodeToString(data, Base64.DEFAULT);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return encrypted;
    }

    public static String rsa_decrypt(final PrivateKey private_key, final String encrypted) {
        return rsa_decrypt(private_key, encrypted.getBytes());
    }
    public static String rsa_decrypt(final PrivateKey private_key, final byte encrypted[]) {
        String decrypted = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            //byte[] data_encrypted = Base64.getDecoder().decode(encrypted);
            // SDK min 19
            byte[] data_encrypted = android.util.Base64.decode(encrypted, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, private_key);
            byte[] data_decrypted = cipher.doFinal(data_encrypted);

            decrypted = new String(data_decrypted, "utf-8");
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }
    */

    // NOTE:
    // - https://stackoverflow.com/questions/27909435/encode-string-in-android-so-php-would-be-able-to-gzdecompress-it
    // - http://www.lvesu.com/blog/php/function.gzuncompress.php
    /*
    The Android data that starts with 1f8b is a gzip stream. In php you use gzdecode() for that. gzencode() on php makes gzip streams.
    The php data that starts with 789c is a zlib stream. You used gzcompress() to make that, and you would use gzuncompress() to decode it.
    The compressed data contained within both of those streams, starting with 2bce is raw deflate data. You can use gzinflate() to decode that if you happened to make it somewhere, and you can use gzdeflate() to generate raw deflate.
    */
    public static byte[] compress_gzencode(String string) {
        byte[] compressed = null;

        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream(string.length());

            // for ... in PHP
            //DeflaterOutputStream gos = new DeflaterOutputStream(os);

            // for gzdecode in PHP
            GZIPOutputStream gos = new GZIPOutputStream(os);

            gos.write(string.getBytes());
            gos.close();

            compressed = os.toByteArray();
            os.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return compressed;
    }

    public String apis() {
        URL url = null;
        HttpURLConnection conn = null;
        int response_code = 0;
        String response = null;
        OutputStream out_stream = null;
        BufferedReader breader = null;
        BufferedWriter bwriter = null;

        final String host = "http://192.168.0.x/test/app_api.php";
        final String timestamp = "" + (int) (System.currentTimeMillis() / 1000L);
        String post_data_timestamp = "\"timestamp\":\"" + timestamp + "\"";
        String post_data =
                "{" +
                        post_data_timestamp + "," +
                        "\"msg1\":\"msg1_val\"," +
                        "\"msg2\":\"msg2_val\"" +
                        "}";

        // Remove: "-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----"
        //String pubkey = "...==";
        String pubkey =
            //"-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsFTHInBER3MeCS3CILGx\n" +
            "UKOjQ+BuUGZ4T5kCxNpJFBJ/Qeabf+xLqat22VK2Vh7hjp6NFccbxUi5EY8DWfQ/\n" +
            "h4RhMPMYQYT/VBYbcl0Lg5FmpyWxj+9oOw69Tr9owutGtYCQdli6IBtNREqnFC73\n" +
            "iOpTK1/lIFpNDgYrmc5rVIDhlcJTgITJBun4kAHI0WmpOEuFQeweVj+3SY5xVmNZ\n" +
            "99lbCHLfNjrao8XJKS8EsjmX55Y3pT1zEdphefrNZzlpnAz17uaC0I9gBdz3AqUw\n" +
            "yDnHJxf/DhZpE/wZYz6DNiQ8Z8mB8mgfy7Y+oMbSKjaYWmlFf6Feo8fnQCccdalF\n" +
            "nvyFJvtkjv1P0dIEuHON+orMGcRr96wwi0XfUDOwopXwRKwQy+Wc8Htaxt1yr+Rs\n" +
            "5HpkYdc/sgSZcGgCgzucsAuYcF0aIXtE/CCBGBBpTmq4irBzW80t9dBE+Qn6LSHH\n" +
            "19t2sax23PN6lfbelKA4+77mFQKrW+C+3GuxTrv9WPN4pf9ekC3k9c6zD5/3U5Fc\n" +
            "wJmHebhIEg/UIw8oflxZp6EtnhFBes/z6CZWYoNcwE7u70zixdJJ8wCjwIzlyOUq\n" +
            "xqY4ZryAImkgw5PKJkNmYjybWIsuab9OuoH9jH7Nl2jW4C335Isw5wCbaJnbBYh1\n" +
            "G/AKBmKGJsIwkQetuoxVa18CAwEAAQ==\n";
            //"-----END PUBLIC KEY-----\n";
        String post_verify = null;
        String encrypted_data = null;
        PublicKey key = rsa_get_public_key_from_string(pubkey);

        // compress & encrypt
        byte compressed_post_data[] = compress_gzencode(post_data);
        encrypted_data = rsa_encrypt(key, compressed_post_data);

        // client's secret (from DB), 40 bytes
        String secret_key = "1234567890123456789012345678901234567890";
        String verify = post_data + secret_key;

        // SHA-256: data + secret key
        {
            // Source:
            // - https://gist.github.com/avilches/750151
            // - https://tavris.tistory.com/30

            try {
                MessageDigest sh = MessageDigest.getInstance("SHA-256");
                //sh.update((post_data + secret_key).getBytes());
                sh.update(verify.getBytes());

                byte byteData[] = sh.digest();
                StringBuffer sb = new StringBuffer();

                for (int i = 0 ; i < byteData.length ; i++) {
                    sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                }

                post_verify = sb.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        try {
            url = new URL( host );
            if ( url == null ) {
                return null;
            }

            conn = (HttpURLConnection)url.openConnection();
            if ( conn == null ) {
                return null;
            }

            conn.setRequestProperty( "User-Agent", "Android" );
            //conn.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded" );
            conn.setReadTimeout( 15000 );
            conn.setConnectTimeout( 15000 );
            conn.setRequestMethod( "POST" );
            conn.setDoInput( true);
            conn.setDoOutput( true );
            conn.setInstanceFollowRedirects( true );


            out_stream = conn.getOutputStream();
            if ( out_stream == null ) {
                return null;
            }

            bwriter = new BufferedWriter( new OutputStreamWriter(out_stream, "UTF-8") );
            if ( bwriter == null ) {
                return null;
            }

            StringBuilder data = new StringBuilder();
            if ( data == null ) {
                return null;
            }
            {
                data.append( URLEncoder.encode("data", "UTF-8") );
                data.append( "=" );
                data.append( URLEncoder.encode(encrypted_data, "UTF-8") );
                data.append( "&" );
                data.append( URLEncoder.encode("timestamp", "UTF-8") );
                data.append( "=" );
                data.append( URLEncoder.encode(timestamp, "UTF-8") );
                data.append( "&" );
                data.append( URLEncoder.encode("verify", "UTF-8") );
                data.append( "=" );
                data.append( URLEncoder.encode(post_verify, "UTF-8") );
            }

            bwriter.write( data.toString() );
            bwriter.flush();
            bwriter.close();

            if ( out_stream != null )
                out_stream.close();


            response_code = conn.getResponseCode();
            if ( response_code == HttpsURLConnection.HTTP_OK ) {
                String line = null;

                breader = new BufferedReader( new InputStreamReader(conn.getInputStream()) );
                if ( breader == null ) {
                    return null;
                }

                response = "";
                while ( (line = breader.readLine()) != null ) {
//                    if ( line.contains( "<br>") ) {
//                        line = line.replace( "<br>", "\r\n" );
//                    }
                    response += line;
                }
                return response;
            }
            else {
                response = null;
            }

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }

        return null;
    }
}
