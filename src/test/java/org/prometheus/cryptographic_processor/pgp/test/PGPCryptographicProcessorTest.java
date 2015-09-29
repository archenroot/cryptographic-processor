package org.prometheus.cryptographic_processor.pgp.test;

import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.prometheus.cryptographic_processor.CryptographicProcessorException;
import org.prometheus.cryptographic_processor.CryptographicProcessorFactory;
import org.prometheus.cryptographic_processor.CryptographicProcessorType;
import org.prometheus.cryptographic_processor.pgp.PGPCryptographicProcessor;

/**
 *
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public class PGPCryptographicProcessorTest {

    @Rule
    public ErrorCollector collector;

    /**
     * PGP Encryption related test variables.
     */
    private final String encInputFileName = "c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt.zip";
    private final String encOutputFileName = "c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt.zip.pgp";
    private final String encPublicKeyFileName = "c:\\cygwin64\\home\\ljech\\.gnupg\\fma2_public_key.asc";
    private final boolean encArmor = false;
    private final boolean encWithIntegrityCheck = true;

    /**
     * PGP Encryption related test variables.
     */
    private final String decInputFileName = "c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt.zip.pgp";
    private final String decPrivateKeyFileName = "c:\\cygwin64\\home\\ljech\\.gnupg\\fma2_private_key.asc";
    private final char[] decPasswd = "Sony123".toCharArray();
    private final String decDefaultFileName = "c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt-decrypted.zip";

    public PGPCryptographicProcessorTest() {
        this.collector = new ErrorCollector();
    }

    @BeforeClass
    public static void setUpClass() {

    }

    @AfterClass
    public static void tearDownClass() {

    }

    @Before
    public void setUp() {
    }

    @After

    public void tearDown() {
    }

    /*
     @Test(expected = CryptographicProcessorException.class)
     public void testException() throws CryptographicProcessorException{
     CryptographicProcessor pgpgCP = null;
     pgpgCP = CryptographicProcessorFactory.buildCryptographicProcessor(CryptographicProcessorType.AES);
     }
     */
    @Test
    public void testPGPEncryptFile() throws CryptographicProcessorException {
        PGPCryptographicProcessor pgpgCP;
        pgpgCP = (PGPCryptographicProcessor) CryptographicProcessorFactory.buildCryptographicProcessor(CryptographicProcessorType.PGP);

        pgpgCP.encryptFileWithKey(
                this.encInputFileName,
                this.encOutputFileName,
                this.encPublicKeyFileName,
                this.encArmor,
                this.encWithIntegrityCheck
        );

        if (new File(this.encOutputFileName).exists()) {
            throw new CryptographicProcessorException(
                    "Expected encrypted file "
                    + this.encOutputFileName
                    + " doesn't exist.");
        }
    }

    @Test
    public void testPGPDecryptFile() throws CryptographicProcessorException {
        PGPCryptographicProcessor pgpgCP;
        pgpgCP = (PGPCryptographicProcessor) CryptographicProcessorFactory.buildCryptographicProcessor(CryptographicProcessorType.PGP);
        pgpgCP.decryptFileWithKey(
                this.decInputFileName,
                this.decPrivateKeyFileName,
                this.decPasswd,
                this.decDefaultFileName);
    }
}
