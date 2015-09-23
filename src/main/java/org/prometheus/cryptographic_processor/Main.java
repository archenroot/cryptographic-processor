/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.prometheus.cryptographic_processor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import static org.prometheus.cryptographic_processor.Main.OutputStreamType.FILE;

/**
 *
 * @author ljech
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public enum OutputStreamType {

        BUFFERED, BYTE_ARRAY, DATA, FILTER, FILE, OBJECT, PIPED
    }

    public static OutputStreamType ost = FILE;
    public static OutputStream os = null;
    public static File outputFile = new File("encrypted");

    public static String fileName = "c:\\devel\\TEST_XZ_LZMA_COMPRESSION.csv";

    /* Convert the message/file content into text form similar to BASE64, so 
     * the result can be transported via email or other services which might
     * automaticly convert the binary non-printable representation of data. 
     * This behaviour need to be prevented in such cases.
     * In case of FTP like transfer it is not usually required.
     */
    boolean armored = false;
/*
    public static void main(String[] args) throws FileNotFoundException, IOException, PGPException {
        switch (ost) {
            case FILE:
                os = new FileOutputStream(outputFile);
                break;

        }

        InputStream encKeyStream = new FileInputStream(new File("c:\\cygwin64\\home\\ljech\\.gnupg\\fma2_public_key.asc"));
        PGPPublicKey encKey = Encrypt.readPublicKey(encKeyStream);
        LOGGER.trace("key created on: " + encKey.getCreationTime());

    }
    */
}
