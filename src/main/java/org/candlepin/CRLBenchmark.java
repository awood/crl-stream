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

import org.candlepin.util.X509CRLEntryStream;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class CRLBenchmark {
    private File crlFile;

    @Benchmark
    @Fork(value = 1,
        jvmArgsAppend = {"-Xloggc:gc_stream.log", "-verbose:gc", "-XX:+PrintGCDetails", "-XX:+PrintGCTimeStamps"})
    public void stream() {
        X509CRLEntryStream stream = null;
        try {
            List<BigInteger> l = new LinkedList<BigInteger>();

            stream = new X509CRLEntryStream(crlFile);
            while (stream.hasNext()) {
                l.add(stream.next().getSerialNumber());
            }

            if (!"1999999".equals(l.get(1999999).toString())) {
                throw new RuntimeException("CRL list read in is incorrect");
            } else {
                System.out.println("Read " + l.size() + " entries");
            }
        }
        catch (IOException e) {
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

    @Benchmark
    @Fork(value = 1,
        jvmArgsAppend = {"-Xloggc:gc_in_memory.log", "-verbose:gc", "-XX:+PrintGCDetails", "-XX:+PrintGCTimeStamps"})
    public void inMemory() {
        InputStream stream = null;
        try {
            List<BigInteger> l = new LinkedList<BigInteger>();

            stream = new BufferedInputStream(new FileInputStream(crlFile));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(stream);

            for (X509CRLEntry entry : crl.getRevokedCertificates()) {
                l.add(entry.getSerialNumber());
            }

            if (!"1999999".equals(l.get(1999999).toString())) {
                throw new RuntimeException("CRL list read in is incorrect");
            }
            else {
                System.out.println("Read " + l.size() + " entries");
            }
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
        X500Name issuer = new X500Name("CN=Test Issuer");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Provider bc = new BouncyCastleProvider();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(bc)
            .build(keyPair.getPrivate());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());

        for (int i = 0; i < 2000000; i++) {
            crlBuilder.addCRLEntry(new BigInteger(String.valueOf(i)), new Date(), CRLReason.unspecified);
        }

        X509CRLHolder holder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter().setProvider(bc).getCRL(holder);

        crlFile = File.createTempFile("crl", ".der");
        System.out.println("\nWrote test crl to " + crlFile.getAbsolutePath());
        FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        crlFile.delete();
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(CRLBenchmark.class.getSimpleName())
            .shouldFailOnError(true)
            .build();

        new Runner(opt).run();
    }
}
