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

import static org.candlepin.test.MatchesPattern.*;
import static org.junit.Assert.*;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public class X509CRLEntryStreamTest {
    private static final BouncyCastleFipsProvider BCFIPS = new BouncyCastleFipsProvider();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private File derFile;
    private File pemFile;

    private X500Name issuer;
    private ContentSigner signer;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        URL url = X509CRLEntryStreamTest.class.getClassLoader().getResource("crl.der");
        derFile = new File(url.getFile());

        url = X509CRLEntryStreamTest.class.getClassLoader().getResource("crl.pem");
        pemFile = new File(url.getFile());

        issuer = new X500Name("CN=Test Issuer");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(BCFIPS)
            .build(keyPair.getPrivate());
    }

    private BigInteger getSerial(TBSCertList.CRLEntry c) {
        return c.getUserCertificate().getValue();
    }

    @Test
    public void testIterateOverSerials() throws Exception {
        InputStream referenceStream = new FileInputStream(derFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL referenceCrl = (X509CRL) cf.generateCRL(referenceStream);

        Set<BigInteger> referenceSerials = new HashSet<BigInteger>();

        for (X509CRLEntry entry : referenceCrl.getRevokedCertificates()) {
            referenceSerials.add(entry.getSerialNumber());
        }

        X509CRLEntryStream stream = new X509CRLEntryStream(derFile);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(getSerial(stream.next()));
            }

            assertEquals(referenceSerials, streamedSerials);
        }
        finally {
            referenceStream.close();
            stream.close();
        }
    }

    @Test
    public void testIterateOverEmptyCrl() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        AuthorityKeyIdentifier identifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier
            (keyPair.getPublic());

        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, identifier);
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("127")));

        X509CRLHolder holder = crlBuilder.build(signer);

        File noUpdateTimeCrl = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(noUpdateTimeCrl, holder.getEncoded());

        X509CRLEntryStream stream = new X509CRLEntryStream(noUpdateTimeCrl);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(getSerial(stream.next()));
            }

            assertEquals(0, streamedSerials.size());
        }
        finally {
            stream.close();
        }
    }

    @Test
    public void testIterateOverEmptyCrlWithNoExtensions() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());

        X509CRLHolder holder = crlBuilder.build(signer);

        File noUpdateTimeCrl = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(noUpdateTimeCrl, holder.getEncoded());

        X509CRLEntryStream stream = new X509CRLEntryStream(noUpdateTimeCrl);

        thrown.expect(IllegalStateException.class);
        thrown.expectMessage(matchesPattern("v1.*"));

        try {
            while (stream.hasNext()) {
                stream.next();
            }
        }
        finally {
            stream.close();
        }
    }

    @Test
    public void testCRLwithoutUpdateTime() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        AuthorityKeyIdentifier identifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier
            (keyPair.getPublic());

        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, identifier);
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("127")));
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);

        X509CRLHolder holder = crlBuilder.build(signer);

        File noUpdateTimeCrl = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(noUpdateTimeCrl, holder.getEncoded());

        X509CRLEntryStream stream = new X509CRLEntryStream(noUpdateTimeCrl);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(getSerial(stream.next()));
            }

            assertEquals(1, streamedSerials.size());
            assertTrue(streamedSerials.contains(new BigInteger("100")));
        }
        finally {
            stream.close();
        }
    }

    @Test
    public void testPemReadThroughBase64Stream() throws Exception {
        /* NB: Base64InputStream only takes base64.  The "-----BEGIN X509 CRL-----" and
         * corresponding footer must be removed.  Luckily in Base64InputStream stops the
         * minute it sees a padding character and our test file has some padding.  Thus,
         * we don't need to worry about removing the footer.  If the Base64 file didn't
         * require padding, I'm not sure what happens so the footer should be removed
         * somehow for real uses */

        InputStream referenceStream = new BufferedInputStream(new FileInputStream(pemFile));
        byte[] header = "-----BEGIN X509 CRL-----".getBytes("ASCII");
        Streams.readFully(referenceStream, header);

        referenceStream = new Base64InputStream(referenceStream);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL referenceCrl = (X509CRL) cf.generateCRL(referenceStream);

        Set<BigInteger> referenceSerials = new HashSet<BigInteger>();

        for (X509CRLEntry entry : referenceCrl.getRevokedCertificates()) {
            referenceSerials.add(entry.getSerialNumber());
        }

        X509CRLEntryStream stream = new X509CRLEntryStream(derFile);
        try {
            Set<BigInteger> streamedSerials = new HashSet<BigInteger>();
            while (stream.hasNext()) {
                streamedSerials.add(getSerial(stream.next()));
            }

            assertEquals(referenceSerials, streamedSerials);
        }
        finally {
            referenceStream.close();
            stream.close();
        }
    }
}
