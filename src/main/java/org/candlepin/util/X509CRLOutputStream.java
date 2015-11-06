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

import static org.bouncycastle.asn1.DERTags.*;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.io.Streams;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

public class X509CRLOutputStream {
    private boolean locked = false;

    private List<DERSequence> newEntries;

    private InputStream crlIn;
    private RSAPrivateKey key;

    private Digest hasher;
    private Integer originalLength;

    private AlgorithmIdentifier signingAlg;
    private AlgorithmIdentifier digestAlg;

    public static final AlgorithmIdentifier DEFAULT_ALGORITHM_ID = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
    public static final AlgorithmIdentifier DEFAULT_DIGEST_ID = new DefaultDigestAlgorithmIdentifierFinder().find(DEFAULT_ALGORITHM_ID);

    public X509CRLOutputStream(File crlToChange, RSAPrivateKey key, String algorithmName) throws FileNotFoundException, CryptoException {
        this.newEntries = new LinkedList<DERSequence>();
        this.crlIn = new BufferedInputStream(new FileInputStream(crlToChange));
        this.key = key;

        if (!algorithmName.contains("RSA")) {
            throw new IllegalArgumentException("This class is only compatible with RSA signing.");
        }
        this.signingAlg = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);
        this.digestAlg = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlg);

        this.hasher = createDigest(digestAlg);
    }

    protected static Digest createDigest(AlgorithmIdentifier digAlg) throws CryptoException {
        Digest dig;

        if (digAlg.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1)) {
            dig = new SHA1Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224)) {
            dig = new SHA224Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256)) {
            dig = new SHA256Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha384)) {
            dig = new SHA384Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha512)) {
            dig = new SHA384Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md5)) {
            dig = new MD5Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md4)) {
            dig = new MD4Digest();
        }
        else {
            throw new CryptoException("cannot recognise digest");
        }

        return dig;
    }

    public X509CRLOutputStream(File crlToChange, RSAPrivateKey key) throws FileNotFoundException, CryptoException {
        this(crlToChange, key, "SHA256withRSA");
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void add(BigInteger serial, Date date, int reason) {
        if (locked) {
            throw new IllegalStateException("Cannot add to a locked stream.");
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERInteger(serial));
        v.add(new Time(date));

        if (reason != 0) {
            CRLReason crlReason = new CRLReason(reason);
            Vector extOids = new Vector();
            Vector extValues = new Vector();
            try {
                extOids.addElement(X509Extension.reasonCode);
                extValues.addElement(new X509Extension(false, new DEROctetString(crlReason.getEncoded())));
            }
            catch (IOException e) {
                throw new IllegalArgumentException("Could not encode reason: " + e);
            }
            v.add(new X509Extensions(extOids, extValues));
        }

        newEntries.add(new DERSequence(v));
    }

    public synchronized void lock() {
        if (locked) {
            throw new IllegalStateException("This stream is already locked.");
        }

        locked = true;
    }

    public void write(OutputStream out) throws IOException {
        if (!locked) {
            throw new IllegalStateException("The instance must be locked before writing.");
        }

        originalLength = handleHeader(out);

        while (originalLength > 0) {
            echoTag(out);
            int length = echoLength(out);
            echoValue(out, length);
        }

        // Read SignatureAlgorithm on old CRL and throw an exception if it doesn't
        // match expectations.
        ASN1InputStream asn1In = null;
        try {
            asn1In = new ASN1InputStream(crlIn);
            ASN1Sequence algSeq = (ASN1Sequence) asn1In.readObject();
            AlgorithmIdentifier referenceAlgId = new AlgorithmIdentifier(algSeq);

            if (!referenceAlgId.equals(signingAlg)) {
                throw new IllegalStateException(
                    "Signing algorithm mismatch.  This will result in an encoding error!  " +
                        "Got " + referenceAlgId.getAlgorithm() + " but expected " + signingAlg.getAlgorithm());
            }
        } finally {
            IOUtils.closeQuietly(asn1In);
        }

        // Write the new entries into the new CRL
        for (DERSequence entry : newEntries) {
            out.write(entry.getDEREncoded());
        }

        out.write(signingAlg.getDEREncoded());

        // Build the digest
        RSADigestSigner signer = new RSADigestSigner(hasher);
        signer.init(true, new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent()));
        try {
            byte[] signature = signer.generateSignature();

            DERBitString signatureBits = new DERBitString(signature);
            out.write(signatureBits.getDEREncoded());
        }
        catch (DataLengthException e) {
            throw new IOException("Could not sign", e);
        }
        catch (CryptoException e) {
            throw new IOException("Could not sign", e);
        }
    }

    protected int rebuildTag(int tag, int tagNo) {
        // FIXME this code is assuming a 1 byte tag
        return tag;
    }

    protected int echoTag(OutputStream out) throws IOException {
        int tag = readTag(crlIn);
        int tagNo = readTagNumber(crlIn, tag);
        out.write(rebuildTag(tag, tagNo));
        hasher.update(new Integer(tag).byteValue());
        return tagNo;
    }

    protected int echoLength(OutputStream out) throws IOException {
        return inflateLength(out, 0);
    }

    protected int inflateLength(OutputStream out, int addedLength) throws IOException {
        int length = readLength(crlIn) + addedLength;
        writeLength(out, length);
        hasher.update(new Integer(length).byteValue());
        return length;
    }

    protected void writeLength(OutputStream out, int length) throws IOException {
        if (length > 127) {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0) {
                size++;
            }

            out.write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8) {
                out.write((byte)(length >> i));
            }
        }
        else {
            out.write((byte)length);
        }
    }

    private void echoValue(OutputStream out, int length) throws IOException {
        byte[] item = new byte[length];
        readFullyAndTrack(crlIn, item);
        out.write(item);
        hasher.update(item, 0, item.length);
    }

    private int handleHeader(OutputStream out) throws IOException {
        int newEntriesLength = 0;
        for (DERSequence s : newEntries) {
            newEntriesLength += s.getDEREncoded().length;
        }

        int tag = readTag(crlIn);
        int length = readLength(crlIn) + newEntriesLength;

        // NB: The top level sequence isn't part of the signature
        out.write(tag);

        /* XXX If the algorithm signature on the original CRL doesn't match
         * what we are using, this will not work since the signature lengths
         * could be/will be different.  If that is the case, we're doomed right here
         * because at this point we don't know the old signature type and signature length
         * so we can't subtract those from the total length.
         */
        writeLength(out, length);

        // Now we are in the TBSCertList
        echoTag(out);
        inflateLength(out, newEntriesLength);

        int tagNo = DERTags.NULL;
        while (true) {
            tagNo = echoTag(out);
            length = echoLength(out);
            echoValue(out, length);

            if (tagNo == GENERALIZED_TIME || tagNo == UTC_TIME) {
                break;
            }
        }

        // Now we have to deal with the potential for an optional nextUpdate field
        tagNo = echoTag(out);

        if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
            length = echoLength(out);
            echoValue(out, length);
            echoTag(out);
        }

        length = inflateLength(out, newEntriesLength);
        int originalLength = length - newEntriesLength;

        return originalLength;
    }

    protected void readFullyAndTrack(InputStream s, byte[]  bytes) throws IOException {
        if (Streams.readFully(s, bytes) != bytes.length) {
            throw new EOFException("EOF encountered in middle of object");
        }

        if (originalLength != null) {
            originalLength -= bytes.length;
        }
    }

    /**
     * Read a single byte and decrement the field holding the length of the
     * revokedCertificates sequence accordingly.
     *
     * @param s the stream to read from
     * @return an integer representing the byte read.
     * @throws IOException
     */
    protected int readAndTrack(InputStream s) throws IOException {
        int i = s.read();
        if (originalLength != null) {
            originalLength--;
        }
        return i;
    }

    protected int readTag(InputStream s) throws IOException {
        int tag = readAndTrack(s);
        if (tag <= 0) {
            if (tag == 0) {
                throw new IOException("unexpected end-of-contents marker");
            }

            throw new IOException("negative tag value");
        }
        return tag;
    }

    protected int readTagNumber(InputStream s, int tag) throws IOException {
        int tagNo = tag & 0x1f;

        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        if (tagNo == 0x1f) {
            // FIXME not supporting arbitrary tags is lousy.  RFC 5280 that a CRL doesn't use any non-universal tags,
            // but it's not a general solution
            throw new IllegalStateException("This class does not support tags that are not universal.");
        }

        return tagNo;
    }

    /**
     * Read the length header from an input stream and return the length read.
     *
     * This code is a slightly adapted version of the code in BouncyCastle's
     * ASN1InputStream.
     *
     * @param s
     * @return
     * @throws IOException
     */
    protected int readLength(InputStream s) throws IOException {
        int length = readAndTrack(s);
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        }

        // indefinite-length encoding
        if (length == 0x80) {
            // We don't support this and the CRL spec shouldn't encounter any of these
            // since indefinite length formats are forbidden in DER.
            throw new IOException("Indefinite length encoding detected." +
                "  Check that input is DER and not BER/CER.");
            // return -1;
        }

        if (length > 127) {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4) {
                throw new IOException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++) {
                int next = readAndTrack(s);

                if (next < 0) {
                    throw new EOFException("EOF found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0) {
                throw new IOException("corrupted stream - negative length found");
            }
        }

        return length;
    }
}
