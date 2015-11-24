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
import org.bouncycastle.jce.provider.X509CRLEntryObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.interfaces.RSAPrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public class X509CRLStreamWriterTest {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private X500Name issuer;
    private ContentSigner signer;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        issuer = new X500Name("CN=Test Issuer");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(BC)
            .build(keyPair.getPrivate());
    }

    class MatchesPattern extends TypeSafeMatcher<String> {
        private String pattern;

        public MatchesPattern(String pattern) {
            this.pattern = pattern;
        }

        @Override
        protected boolean matchesSafely(String item) {
            return item.matches(pattern);
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("matches pattern ")
                .appendValue(pattern);
        }

        @Override
        protected void describeMismatchSafely(String item, Description mismatchDescription) {
            mismatchDescription.appendText("does not match");
        }
    }

    @Test
    public void testAddEntryToCRL() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);
        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        File outfile = new File(folder.getRoot(), "new.crl");
        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate());
        stream.add(new BigInteger("9000"), new Date(), 0);
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();

        InputStream changedStream = new BufferedInputStream(new FileInputStream(outfile));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL changedCrl = (X509CRL) cf.generateCRL(changedStream);
        changedCrl.verify(keyPair.getPublic(), BC);

        Set<BigInteger> discoveredSerials = new HashSet<BigInteger>();

        for (X509CRLEntry entry : changedCrl.getRevokedCertificates()) {
            discoveredSerials.add(entry.getSerialNumber());
        }

        Set<BigInteger> expected = new HashSet<BigInteger>();
        expected.add(new BigInteger("100"));
        expected.add(new BigInteger("9000"));

        assertEquals(expected, discoveredSerials);
    }

    @Test
    public void testDeleteEntryFromCRL() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);
        crlBuilder.addCRLEntry(new BigInteger("101"), new Date(), CRLReason.unspecified);
        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        File outfile = new File(folder.getRoot(), "new.crl");

        CRLEntryValidator validator = new CRLEntryValidator() {
            @Override
            public boolean shouldDelete(X509CRLEntryObject entry) {
                return entry.getSerialNumber().equals(new BigInteger("101"));
            }
        };

        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate());
        stream.collectDeadEntries(crlToChange, validator);
        stream.add(new BigInteger("9000"), new Date(), 0);
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();

        InputStream changedStream = new BufferedInputStream(new FileInputStream(outfile));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL changedCrl = (X509CRL) cf.generateCRL(changedStream);
        changedCrl.verify(keyPair.getPublic(), BC);

        Set<BigInteger> discoveredSerials = new HashSet<BigInteger>();

        for (X509CRLEntry entry : changedCrl.getRevokedCertificates()) {
            discoveredSerials.add(entry.getSerialNumber());
        }

        Set<BigInteger> expected = new HashSet<BigInteger>();
        expected.add(new BigInteger("100"));
        expected.add(new BigInteger("9000"));

        assertEquals(expected, discoveredSerials);
    }

    @Test
    public void testModifyUpdatedTime() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);
        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        Thread.sleep(1000);

        File outfile = new File(folder.getRoot(), "new.crl");
        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate());
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();

        InputStream changedStream = new BufferedInputStream(new FileInputStream(outfile));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL changedCrl = (X509CRL) cf.generateCRL(changedStream);
        changedCrl.verify(keyPair.getPublic(), BC);

        assertTrue("Error: CRL thisUpdate field unmodified",
            crl.getThisUpdate().before(changedCrl.getThisUpdate()));
    }

    @Test
    public void testModifyNextUpdateTime() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);

        Calendar c = Calendar.getInstance();
        c.add(Calendar.DATE, 1);
        Date nextUpdate = c.getTime();

        crlBuilder.setNextUpdate(nextUpdate);
        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "test.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        Thread.sleep(1000);

        File outfile = new File(folder.getRoot(), "new.crl");
        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate());
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();

        InputStream changedStream = new BufferedInputStream(new FileInputStream(outfile));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL changedCrl = (X509CRL) cf.generateCRL(changedStream);
        changedCrl.verify(keyPair.getPublic(), BC);

        assertTrue("Error: CRL nextUpdate field unmodified",
            crl.getNextUpdate().before(changedCrl.getNextUpdate()));
    }

    @Test
    public void testSignatureMismatch() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);

        ContentSigner badSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
            .setProvider(BC)
            .build(keyPair.getPrivate());

        X509CRLHolder holder = crlBuilder.build(badSigner);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "sha1signed.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        File outfile = new File(folder.getRoot(), "new.crl");

        thrown.expect(IllegalStateException.class);
        thrown.expectMessage(
            new MatchesPattern("Signing algorithm mismatch.*"));

        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate());
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();
    }

    @Test
    public void testNonDefaultSignature() throws Exception {
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(new BigInteger("100"), new Date(), CRLReason.unspecified);

        String signingAlg = "SHA1WithRSAEncryption";
        ContentSigner sha1Signer = new JcaContentSignerBuilder(signingAlg)
            .setProvider(BC)
            .build(keyPair.getPrivate());

        X509CRLHolder holder = crlBuilder.build(sha1Signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);

        File crlToChange = new File(folder.getRoot(), "sha1signed.crl");
        FileUtils.writeByteArrayToFile(crlToChange, crl.getEncoded());

        File outfile = new File(folder.getRoot(), "new.crl");
        X509CRLStreamWriter stream = new X509CRLStreamWriter(crlToChange,
            (RSAPrivateKey) keyPair.getPrivate(), signingAlg);
        stream.add(new BigInteger("9000"), new Date(), 0);
        stream.lock();
        OutputStream o = new BufferedOutputStream(new FileOutputStream(outfile));
        stream.write(o);
        o.close();

        InputStream changedStream = new BufferedInputStream(new FileInputStream(outfile));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL changedCrl = (X509CRL) cf.generateCRL(changedStream);
        changedCrl.verify(keyPair.getPublic(), BC);

        Set<BigInteger> discoveredSerials = new HashSet<BigInteger>();

        for (X509CRLEntry entry : changedCrl.getRevokedCertificates()) {
            discoveredSerials.add(entry.getSerialNumber());
        }

        Set<BigInteger> expected = new HashSet<BigInteger>();
        expected.add(new BigInteger("100"));
        expected.add(new BigInteger("9000"));

        assertEquals(expected, discoveredSerials);
    }
}
