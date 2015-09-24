/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor;

import org.prometheus.cryptographic_processor.pgp.PGPCryptographicProcessor;
import org.prometheus.cryptographic_processor.CryptographicProcessorType;

/**
 *
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public class CryptographicProcessorFactory {
    public static CryptographicProcessor buildCryptographicProcessor(CryptographicProcessorType cryptographicProcessorType) throws CryptographicProcessorException{
        CryptographicProcessor cryptographicProcessor = null;
        switch (cryptographicProcessorType){
            case PGP:
                cryptographicProcessor = new PGPCryptographicProcessor();
                break;
            default:
                String message = "Factory cannot create instance of specific CryptographicProcessor, "
                        + "because provided processor type is not known or unsupported. Provided value: " + cryptographicProcessorType;
                throw new CryptographicProcessorException(message);
        }
        
        return cryptographicProcessor;
    }
}
