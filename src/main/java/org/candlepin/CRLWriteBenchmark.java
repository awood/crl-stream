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
package org.candlepin;

import org.candlepin.util.X509CRLStreamWriter;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class CRLWriteBenchmark {
    private File crlFile;
    private KeyPair keyPair;
    private X500Name issuer;
    private BouncyCastleProvider bc;
    private ContentSigner signer;

    @Benchmark
    @Fork(value = 1,
        jvmArgsAppend = {"-Xloggc:gc_stream_write.log", "-verbose:gc", "-XX:+PrintGCDetails", "-XX:+PrintGCTimeStamps"})
    public void stream() {
        OutputStream out = null;
        try {
            X509CRLStreamWriter stream = new X509CRLStreamWriter(crlFile,
                (RSAPrivateKey) keyPair.getPrivate(), (RSAPublicKey) keyPair.getPublic());
            stream.add(new BigInteger("25000000000"), new Date(), CRLReason.unspecified);
            stream.preScan(crlFile).lock();

            File newCrlFile = File.createTempFile("new_crl", ".der");
            out = new BufferedOutputStream(new FileOutputStream(newCrlFile));
            stream.write(out);
            System.out.println("\nWrote new crl to " + newCrlFile.getAbsolutePath());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (out != null) {
                try {
                    out.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Benchmark
    @Fork(value = 1,
        jvmArgsAppend = {"-Xloggc:gc_in_memory_write.log", "-verbose:gc", "-XX:+PrintGCDetails", "-XX:+PrintGCTimeStamps"})
    public void inMemory() {
        ASN1InputStream stream = null;
        try {
            stream = new ASN1InputStream(new BufferedInputStream(new FileInputStream(crlFile)));
            ASN1Primitive o = stream.readObject();

            X509CRLHolder oldCrl = new X509CRLHolder(o.getEncoded());

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
            crlBuilder.addCRL(oldCrl);

            crlBuilder.addCRLEntry(new BigInteger("25000000000"), new Date(), CRLReason.unspecified);

            X509CRLHolder holder = crlBuilder.build(signer);
            X509CRL crl = new JcaX509CRLConverter().setProvider(bc).getCRL(holder);

            File newCrlFile = File.createTempFile("new_crl", ".der");
            FileUtils.writeByteArrayToFile(newCrlFile, crl.getEncoded());
            System.out.println("\nWrote new crl to " + newCrlFile.getAbsolutePath());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (stream != null) {
                try {
                    stream.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Setup(Level.Trial)
    public void buildMassiveCRL() throws Exception {
        issuer = new X500Name("CN=Test Issuer");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        bc = new BouncyCastleProvider();
        signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(bc)
            .build(keyPair.getPrivate());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        AuthorityKeyIdentifier identifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier
            (keyPair.getPublic());
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, identifier);
        /* With a CRL number of 127, incrementing it should cause the number of bytes in the length
         * portion of the TLV to increase by one.*/
        crlBuilder.addExtension(X509Extension.cRLNumber, false, new CRLNumber(new BigInteger("127")));

        for (int i = 0; i < 2000000; i++) {
            crlBuilder.addCRLEntry(new BigInteger(String.valueOf(i)), new Date(), CRLReason.unspecified);
        }


        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(bc).getCRL(holder);

        crlFile = File.createTempFile("crl", ".der");
        System.out.println("\nWrote test crl to " + crlFile.getAbsolutePath());
        FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
    }

    @Setup(Level.Trial)
    public void createKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        crlFile.delete();
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(CRLWriteBenchmark.class.getSimpleName())
            .shouldFailOnError(true)
            .build();

        new Runner(opt).run();
    }
}
