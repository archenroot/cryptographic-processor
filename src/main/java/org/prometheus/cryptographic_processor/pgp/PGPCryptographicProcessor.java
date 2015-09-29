/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor.pgp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
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

    private final GenericResult result;

    /**
     *
     * @throws CryptographicProcessorException
     */
    public PGPCryptographicProcessor() throws CryptographicProcessorException {
        super(CryptographicProcessorType.PGP);
        this.result = GenericResult.getInstance();
        construct();
    }

    /**
     *
     */
    @Override
    protected void construct() {
        log.info("PGP cryptographic processor created.");
    }

    /**
     *
     * @param outputFileName
     * @param inputFileName
     * @param encKeyFileName
     * @param armor
     * @param withIntegrityCheck
     * @throws PGPProcessorException
     */
    public void encryptFileWithKey(
            String inputFileName,
            String outputFileName,
            String encKeyFileName,
            boolean armor,
            boolean withIntegrityCheck) throws PGPProcessorException {
        
        try {
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName))) {
                PGPPublicKey encKey = PGPCustomUtilities.readPublicKey(encKeyFileName);
                KeyBasedLargeFileProcessor.encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
            }
        } catch (IOException | NoSuchProviderException | PGPException ex) {
            throw new PGPProcessorException(ex);
        }
    }

    /**
     *
     * @param inputFileName
     * @param keyFileName
     * @param passwd
     * @param defaultFileName
     * @throws PGPProcessorException
     */
    public void decryptFileWithKey(
            String inputFileName,
            String keyFileName,
            char[] passwd,
            String defaultFileName)
            throws PGPProcessorException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(inputFileName))) {
            InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
            KeyBasedLargeFileProcessor.decryptFile(in, keyIn, passwd, defaultFileName);
            keyIn.close();
        } catch (IOException ex) {
            throw new PGPProcessorException(ex);
        } catch (NoSuchProviderException ex) {
            throw new PGPProcessorException(ex);
        }
    }
}