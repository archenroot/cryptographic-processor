/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.prometheus.cryptographic_processor.pgp.PGPCryptographicProcessor;
import org.prometheus.cryptographic_processor.result.GenericResult;

/**
 * Factory
 * @author Ladislav Jech <archenroot at gmail.com>
 */
public class CryptographicProcessorFactory {
    
    private static final Logger log = LogManager.getLogger();
    static {
        
    }
    
    /**
     * TODO
     * @param cryptographicProcessorType
     * @param cor
     * @return
     */
    public static CryptographicProcessor buildCryptographicProcessor(CryptographicProcessorType cryptographicProcessorType, GenericResult cor){
        return null;
    }

    /**
     *
     * @param cryptographicProcessorType
     * @return
     * @throws CryptographicProcessorException
     */
    public static CryptographicProcessor buildCryptographicProcessor(CryptographicProcessorType cryptographicProcessorType) throws CryptographicProcessorException{
        log.entry();
        CryptographicProcessor cryptographicProcessor = null;
        switch (cryptographicProcessorType){
            case PGP:
                //log.debug(MARKER, null, PGP);
                cryptographicProcessor = new PGPCryptographicProcessor();
                break;
            case AES:
                String aesMessage = "Factory cannot create instance of specific CryptographicProcessor, "
                        + "because provided processor type is not known or unsupported. Provided value: " + cryptographicProcessorType;
                log.fatal(aesMessage);
                throw new CryptographicProcessorException(aesMessage);
            default:
                String defaultMessage = "Factory cannot create instance of specific CryptographicProcessor, "
                        + "because provided processor type is not known or unsupported. Provided value: " + cryptographicProcessorType;
                log.fatal(defaultMessage);
                throw new CryptographicProcessorException(defaultMessage);
        }
        
        log.exit();
        return cryptographicProcessor;
    }
}
