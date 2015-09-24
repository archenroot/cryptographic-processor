/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor.pgp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.prometheus.cryptographic_processor.CryptographicProcessor;
import org.prometheus.cryptographic_processor.CryptographicProcessorType;

/**
 *
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public final class PGPCryptographicProcessor extends CryptographicProcessor {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Marker PGP_CRYPTO_MARKER = MarkerManager.getMarker("PGP_CRYPTO");
    private static final Marker PGP_CRYPTO_ENCRYPT_MARKER = MarkerManager.getMarker("PGP_CRYPTO_ENCRYPT").setParents(PGP_CRYPTO_MARKER);
    private static final Marker PGP_CRYPTO_DECRYPT_MARKER = MarkerManager.getMarker("PGP_CRYPTO_DECRYPT").setParents(PGP_CRYPTO_MARKER);
    
   public PGPCryptographicProcessor(){
        super(CryptographicProcessorType.PGP);
        process();
    }
    @Override
    protected void process() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }
}
