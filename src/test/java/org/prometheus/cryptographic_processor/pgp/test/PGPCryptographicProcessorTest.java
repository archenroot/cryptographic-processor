package org.prometheus.cryptographic_processor.pgp.test;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.prometheus.cryptographic_processor.CryptographicProcessor;
import org.prometheus.cryptographic_processor.CryptographicProcessorException;
import org.prometheus.cryptographic_processor.CryptographicProcessorFactory;
import org.prometheus.cryptographic_processor.CryptographicProcessorType;
import org.prometheus.cryptographic_processor.pgp.KeyBasedLargeFileProcessor;
import org.prometheus.cryptographic_processor.pgp.PGPCryptographicProcessor;

/**
 *
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public class PGPCryptographicProcessorTest {
    
    public PGPCryptographicProcessorTest() {
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

    @Test(expected = CryptographicProcessorException.class)
    public void testException() throws CryptographicProcessorException{
        CryptographicProcessor pgpgCP = null;
            pgpgCP = CryptographicProcessorFactory.buildCryptographicProcessor(CryptographicProcessorType.AES);
    }
   
    @Test
    public void testPGPEncryptFile() throws CryptographicProcessorException{
        PGPCryptographicProcessor pgpgCP = null;
        pgpgCP = (PGPCryptographicProcessor) CryptographicProcessorFactory.buildCryptographicProcessor(CryptographicProcessorType.PGP);
        pgpgCP.encryptFileWithKey("c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt.zip.pgp",
                "c:\\cygwin64\\home\\ljech\\SCEE_TR0000208-090-CY_20150428.txt.zip",
                "c:\\cygwin64\\home\\ljech\\.gnupg\\fma2_public_key.asc",
                false,
                true);
    }
    
    @Test
    public void testPGPDecryptFile(){
        
    }
    
  
}
