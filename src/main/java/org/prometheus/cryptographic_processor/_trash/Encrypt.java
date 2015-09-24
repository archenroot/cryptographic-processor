package org.prometheus.cryptographic_processor._trash;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;


public class Encrypt {

    private static int BUFFER_SIZE = 4096;
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    
    public static PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection((Collection<PGPPublicKeyRing>) in);

        //
        // we just loop through the collection till we find a key suitable for
        // encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }
    
    /*
     public static String encryptToFile(String inputStr, String keyFile, String outFile) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] original = inputStr.getBytes();

        FileInputStream pubKey = new FileInputStream(keyFile);
        byte[] encrypted = encrypt(original, readPublicKey(pubKey), null,
                true, true);

        FileOutputStream dfis = new FileOutputStream(outFile);
        dfis.write(encrypted);
        dfis.close();

        return new String(encrypted);
    }
     */
    private static void encryptFile(
            OutputStream out, 
            String fileName, 
            PGPPublicKey encKey, 
            PGPSecretKey pgpSec, 
            boolean armor, 
            boolean withIntegrityCheck, 
            char[] pass) throws IOException, NoSuchProviderException, PGPException {
        
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            PGPEncryptedDataGenerator encGen
                    = new PGPEncryptedDataGenerator(
                            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(
                                    new SecureRandom())
                            .setProvider("BC"));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            OutputStream encryptedOut = encGen.open(out, new byte[BUFFER_SIZE]);

            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            OutputStream compressedData = comData.open(encryptedOut);

        //OutputStream compressedData = encryptedOut;
            PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
            PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                    pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
            sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
            Iterator it = pgpSec.getPublicKey().getUserIDs();
            if (it.hasNext()) {
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, (String) it.next());
                sGen.setHashedSubpackets(spGen.generate());
            }
            //BCPGOutputStream bOut = new BCPGOutputStream(compressedData);
            sGen.generateOnePassVersion(false).encode(compressedData); // bOut

            File file = new File(fileName);
            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
            OutputStream lOut = lGen.open(compressedData, PGPLiteralData.BINARY, file.getName(), new Date(),
                    new byte[BUFFER_SIZE]); //bOut
            FileInputStream fIn = new FileInputStream(file);
            int ch;

            while ((ch = fIn.read()) >= 0) {
                lOut.write(ch);
                sGen.update((byte) ch);
            }

            fIn.close();
            lOut.close();
            lGen.close();

            sGen.generate().encode(compressedData);

        //bOut.close();
            comData.close();
            compressedData.close();

            encryptedOut.close();
            encGen.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }
}
