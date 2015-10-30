/**
 * Copyright (c) 2009 - 2012 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package org.candlepin.util;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.jce.provider.X509CRLParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public class X509CRLStreamTest {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private File crlFile;
    private X500Name issuer;
    private ContentSigner signer;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        URL url = X509CRLStreamTest.class.getClassLoader().getResource("crl.der");
        crlFile = new File(url.getFile());
        issuer = new X500Name("CN=Test Issuer");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(BC)
            .build(keyPair.getPrivate());
    }

    @Test
    public void testIterateOverSerials() throws Exception {
        X509CRLParser referenceParser = new X509CRLParser();
        InputStream referenceStream = new FileInputStream(crlFile);
        referenceParser.engineInit(referenceStream);

        X509CRLObject referenceCRL = (X509CRLObject) referenceParser.engineRead();

        Set<BigInteger> referenceSerials = new HashSet<BigInteger>();

        for (Object o : referenceCRL.getRevokedCertificates()) {
            X509CRLEntry entry = (X509CRLEntry) o;
            referenceSerials.add(entry.getSerialNumber());
        }

        X509CRLStream stream = new X509CRLStream(crlFile);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(stream.next());
            }

            assertEquals(referenceSerials, streamedSerials);
        }
        finally {
            stream.close();
        }
    }

    @Test
    public void testCRLwithoutUpdateTime() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);
        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File noUpdateTimeCrl = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(noUpdateTimeCrl, crl.getEncoded());

        X509CRLStream stream = new X509CRLStream(noUpdateTimeCrl);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(stream.next());
            }

            assertEquals(1, streamedSerials.size());
            assertTrue(streamedSerials.contains(new BigInteger("100")));
        }
        finally {
            stream.close();
        }
    }
}
