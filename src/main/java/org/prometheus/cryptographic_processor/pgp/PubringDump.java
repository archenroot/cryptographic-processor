package org.prometheus.cryptographic_processor.pgp;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Iterator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

/**
 * Basic class which just lists the contents of the public key file passed
 * as an argument. If the file contains more than one "key ring" they are
 * listed in the order found.
 */
public class PubringDump 
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static String getAlgorithm(
        int    algId)
    {
        switch (algId)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
            return "RSA_GENERAL";
        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            return "RSA_ENCRYPT";
        case PublicKeyAlgorithmTags.RSA_SIGN:
            return "RSA_SIGN";
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            return "ELGAMAL_ENCRYPT";
        case PublicKeyAlgorithmTags.DSA:
            return "DSA";
        case PublicKeyAlgorithmTags.EC:
            return "EC";
        case PublicKeyAlgorithmTags.ECDSA:
            return "ECDSA";
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            return "ELGAMAL_GENERAL";
        case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
            return "DIFFIE_HELLMAN";
        }

        return "unknown";
    }
    /* Method to print out Public key ring collection
     * No parameter indicates that this function will try to locate default
     * pubring by itslef.
    */
    public static void printPubringDump(){
        // TODO
    }
    
    public static void printPubringDump(String pubringFile) throws PGPProcessingException{
    
        try {
            //String pubring = "c:\\cygwin64\\home\\ljech\\.gnupg\\pubring.gpg";
            //String pubringFile = "c:\\cygwin64\\home\\ljech\\.gnupg\\pubring.gpg";
            //
            // Read the public key rings
            //
            
            PGPPublicKeyRingCollection pubRings =
                    new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(
                                    new FileInputStream(pubringFile)
                            ),
                            new JcaKeyFingerprintCalculator()
                    );
            
            Iterator    rIt = pubRings.getKeyRings();
            
            while (rIt.hasNext())
            {
                PGPPublicKeyRing    pgpPub = (PGPPublicKeyRing)rIt.next();
                
                try
                {
                    pgpPub.getPublicKey();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    continue;
                }
                
                Iterator    it = pgpPub.getPublicKeys();
                boolean     first = true;
                while (it.hasNext())
                {
                    PGPPublicKey    pgpKey = (PGPPublicKey)it.next();
                    Iterator userIdIterator = pgpKey.getUserIDs();
                    while (userIdIterator.hasNext()){
                        LOGGER.info("User ID: " + userIdIterator.next());
                    }
                    
                    if (first)
                    {
                        LOGGER.info("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                        
                        first = false;
                    }
                    else
                    {
                        LOGGER.info("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                    }

                    LOGGER.info("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
                    LOGGER.info("            Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
                    LOGGER.info("            Valid Seconds: " + pgpKey.getValidSeconds());
                }
            }
        } catch (IOException ex) {
            String msg = "TODO";
            LOGGER.error(msg);
            throw new PGPProcessingException(msg,ex);
        } catch (PGPException ex) {
            String msg = "TODO";
            LOGGER.error(msg);
            throw new PGPProcessingException(msg,ex);
        }
    }
    public static void main(String[] args)
        throws Exception
    {
        
        String pubring = "c:\\cygwin64\\home\\ljech\\.gnupg\\pubring.gpg";
        //String pubring = "c:\\cygwin64\\home\\ljech\\.gnupg\\pubring.gpg";
        //
        // Read the public key rings
        //
        PGPPublicKeyRingCollection    pubRings = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(new FileInputStream(pubring)), new JcaKeyFingerprintCalculator());

        Iterator    rIt = pubRings.getKeyRings();
            
        while (rIt.hasNext())
        {
            PGPPublicKeyRing    pgpPub = (PGPPublicKeyRing)rIt.next();
            
            try
            {
                pgpPub.getPublicKey();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                continue;
            }

            Iterator    it = pgpPub.getPublicKeys();
            boolean     first = true;
            while (it.hasNext())
            {
                PGPPublicKey    pgpKey = (PGPPublicKey)it.next();
                Iterator userIdIterator = pgpKey.getUserIDs();
                while (userIdIterator.hasNext()){
                        LOGGER.info("User ID: " + userIdIterator.next());
                }
                
                if (first)
                {
                    LOGGER.info("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                    
                    first = false;
                }
                else
                {
                    LOGGER.info("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                }
                
                LOGGER.info("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
                LOGGER.info("            Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
                LOGGER.info("            Valid Seconds: " + pgpKey.getValidSeconds());
            }
        }
    }
}
