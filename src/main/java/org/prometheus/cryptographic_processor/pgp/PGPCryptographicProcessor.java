/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor.pgp;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.bouncycastle.openpgp.PGPException;
import org.prometheus.cryptographic_processor.CryptographicProcessor;
import org.prometheus.cryptographic_processor.CryptographicProcessorException;
import org.prometheus.cryptographic_processor.CryptographicProcessorType;
import org.prometheus.cryptographic_processor.result.GenericResult;

/**
 *
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public final class PGPCryptographicProcessor extends CryptographicProcessor {

    private static final Logger log = LogManager.getLogger();
    private static final Marker PGP_CRYPTO_MARKER = MarkerManager.getMarker("PGP_CRYPTO");
    private static final Marker PGP_CRYPTO_ENCRYPT_MARKER = MarkerManager.getMarker("PGP_CRYPTO_ENCRYPT").setParents(PGP_CRYPTO_MARKER);
    private static final Marker PGP_CRYPTO_DECRYPT_MARKER = MarkerManager.getMarker("PGP_CRYPTO_DECRYPT").setParents(PGP_CRYPTO_MARKER);
    
   public PGPCryptographicProcessor() throws CryptographicProcessorException{
        super(CryptographicProcessorType.PGP);
        construct();
    }
    @Override
    protected void construct() {
       log.info("PGP cryptographic processor created.");
    }
    
    public GenericResult encryptFileWithKey(
            String outputFileName,
            String inputFileName,
            String encKeyFileName,
            boolean armor,
            boolean withIntegrityCheck) throws PGPProcessingException {
            
        
        try {
            KeyBasedLargeFileProcessor.encryptFile(
                    outputFileName,
                    inputFileName,
                    encKeyFileName,
                    armor,
                    withIntegrityCheck);
            return null;
        } catch (IOException ex) {
            throw new PGPProcessingException(ex);
        } catch (NoSuchProviderException ex) {
            throw new PGPProcessingException(ex);
        } catch (PGPException ex) {
            throw new PGPProcessingException(ex);
        }
    }
}
