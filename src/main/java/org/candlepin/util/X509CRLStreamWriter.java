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
import static org.candlepin.util.DERUtil.*;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.DERUTCTime;
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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
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
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Class for adding entries to an X509 in a memory-efficient manner.
 */
public class X509CRLStreamWriter {
    public static final String DEFAULT_ALGORITHM = "SHA256withRSA";

    private boolean locked = false;

    private List<DERSequence> newEntries;

    private InputStream crlIn;
    private RSAPrivateKey key;

    private Digest hasher;
    private Integer originalLength;
    private AtomicInteger count;

    private AlgorithmIdentifier signingAlg;
    private AlgorithmIdentifier digestAlg;

    public X509CRLStreamWriter(File crlToChange, RSAPrivateKey key)
        throws FileNotFoundException, CryptoException {
        this(crlToChange, key, DEFAULT_ALGORITHM);
    }

    public X509CRLStreamWriter(File crlToChange, RSAPrivateKey key, String algorithmName)
        throws FileNotFoundException, CryptoException {
        this.newEntries = new LinkedList<DERSequence>();
        this.crlIn = new BufferedInputStream(new FileInputStream(crlToChange));
        this.key = key;

        if (!algorithmName.contains("RSA")) {
            throw new IllegalArgumentException("This class is only compatible with RSA signing.");
        }
        this.signingAlg = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);
        this.digestAlg = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlg);

        this.hasher = createDigest(digestAlg);
        this.count = new AtomicInteger();
    }

    /**
     * Create an entry to be added to the CRL.
     *
     * @param serial
     * @param date
     * @param reason
     */
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

    /**
     * Locks the stream to prepare it for writing.
     */
    public synchronized void lock() {
        if (locked) {
            throw new IllegalStateException("This stream is already locked.");
        }

        locked = true;
    }

    /**
     * Write a modified CRL to the given output stream.  This method will add each entry provided
     * via the add() method.
     *
     * @param out OutputStream to write to
     * @throws IOException if something goes wrong
     */
    public void write(OutputStream out) throws IOException {
        if (!locked) {
            throw new IllegalStateException("The instance must be locked before writing.");
        }

        originalLength = handleHeader(out);

        while (originalLength > count.get()) {
            echoTag(out, count);
            int length = echoLength(out, count);
            echoValue(out, length, count);
        }

        /* Read SignatureAlgorithm on old CRL and throw an exception if it doesn't
         * match expectations. */
        ASN1InputStream asn1In = null;
        try {
            asn1In = new ASN1InputStream(crlIn);
            ASN1Sequence algSeq = (ASN1Sequence) asn1In.readObject();
            AlgorithmIdentifier referenceAlgId = new AlgorithmIdentifier(algSeq);

            if (!referenceAlgId.equals(signingAlg)) {
                throw new IllegalStateException(
                    "Signing algorithm mismatch.  This will result in an encoding error!  " +
                        "Got " + referenceAlgId.getAlgorithm() + " but expected " +
                        signingAlg.getAlgorithm());
            }
        }
        finally {
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

    protected int handleHeader(OutputStream out) throws IOException {
        int newEntriesLength = 0;
        for (DERSequence s : newEntries) {
            newEntriesLength += s.getDEREncoded().length;
        }

        int tag = readTag(crlIn, null);
        int length = readLength(crlIn, null) + newEntriesLength;

        // NB: The top level sequence isn't part of the signature
        out.write(tag);

        /* If the algorithm signature on the original CRL doesn't match what
         * we are using, this will not work since the signature lengths could
         * be/will be different.  If that is the case, we're doomed right here
         * because at this point we don't know the old signature type and signature
         * length so we can't determine how the total length of the top level sequence
         * will be affected.  We'll report the error when we detect the discrepancy
         * in algorithms later.
         */
        writeLength(out, length);

        // Now we are in the TBSCertList
        echoTag(out);
        inflateLength(out, newEntriesLength);

        int tagNo = DERTags.NULL;
        Date oldThisUpdate = null;
        while (true) {
            tag = readTag(crlIn, null);
            tagNo = readTagNumber(crlIn, tag, null);

            if (tagNo == GENERALIZED_TIME || tagNo == UTC_TIME) {
                oldThisUpdate = readAndReplaceTime(out, tagNo);
                break;
            }
            else {
                out.write(rebuildTag(tag, tagNo));
                length = echoLength(out);
                echoValue(out, length);
            }
        }

        // Now we have to deal with the potential for an optional nextUpdate field
        tag = readTag(crlIn, null);
        tagNo = readTagNumber(crlIn, tag, null);

        if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
            /* It would be possible to take in a desired nextUpdate in the constructor
             * but I'm not sure if the added complexity is worth it.
             */
            offsetNextUpdate(out, tagNo, oldThisUpdate);
            echoTag(out);
        }
        else {
            out.write(rebuildTag(tag, tagNo));
        }

        length = inflateLength(out, newEntriesLength);
        int originalLength = length - newEntriesLength;

        return originalLength;
    }

    /**
     * Write a new nextUpdate time that is the same amount of time ahead of the new thisUpdate time as
     * the old nextUpdate was from the old thisUpdate.
     *
     * @param out
     * @param tagNo
     * @param oldThisUpdate
     * @throws IOException
     */
    protected void offsetNextUpdate(OutputStream out, int tagNo, Date oldThisUpdate) throws IOException {
        int originalLength = readLength(crlIn, null);
        byte[] oldBytes = new byte[originalLength];
        readFullyAndTrack(crlIn, oldBytes, null);

        DERObject oldTime = null;
        if (tagNo == UTC_TIME) {
            DERTaggedObject t = new DERTaggedObject(UTC_TIME, new DEROctetString(oldBytes));
            oldTime = DERUTCTime.getInstance(t, false);
        }
        else {
            DERTaggedObject t = new DERTaggedObject(GENERALIZED_TIME, new DEROctetString(oldBytes));
            oldTime = DERGeneralizedTime.getInstance(t, false);
        }

        /* Determine the time between the old thisUpdate and old nextUpdate and add it
        /* to the new nextUpdate. */
        Date oldNextUpdate = new Time(oldTime).getDate();
        long delta = oldNextUpdate.getTime() - oldThisUpdate.getTime();
        Date newNextUpdate = new Date(new Date().getTime() + delta);

        DERObject newTime = null;
        if (tagNo == UTC_TIME) {
            newTime = new DERUTCTime(newNextUpdate);
        }
        else {
            newTime = new DERGeneralizedTime(newNextUpdate);
        }
        writeNewTime(out, newTime, originalLength);
    }

    /**
     * Replace a time in the ASN1 with the current time.
     *
     * @param out
     * @param tagNo
     * @return the time that was replaced
     * @throws IOException
     */
    protected Date readAndReplaceTime(OutputStream out, int tagNo) throws IOException {
        int originalLength = readLength(crlIn, null);
        byte[] oldBytes = new byte[originalLength];
        readFullyAndTrack(crlIn, oldBytes, null);

        DERObject oldTime = null;
        DERObject newTime = null;
        if (tagNo == UTC_TIME) {
            DERTaggedObject t = new DERTaggedObject(UTC_TIME, new DEROctetString(oldBytes));
            oldTime = DERUTCTime.getInstance(t, false);

            newTime = new DERUTCTime(new Date());
        }
        else {
            DERTaggedObject t = new DERTaggedObject(GENERALIZED_TIME, new DEROctetString(oldBytes));
            oldTime = DERGeneralizedTime.getInstance(t, false);

            newTime = new DERGeneralizedTime(new Date());
        }

        writeNewTime(out, newTime, originalLength);
        return new Time(oldTime).getDate();
    }

    protected void writeNewTime(OutputStream out, DERObject newTime, int originalLength) throws IOException {
        byte[] newEncodedTime = newTime.getDEREncoded();

        InputStream timeIn = new ByteArrayInputStream(newEncodedTime);
        int newTag = readTag(timeIn, null);
        readTagNumber(timeIn, newTag, null);
        int newLength = readLength(timeIn, null);

        /* If the length changes, it's going to create a discrepancy with the length
         * reported in the TBSCertList sequence.  The length could change with the addition
         * or removal of time zone information for example. */
        if (newLength != originalLength) {
            throw new IllegalStateException("Length of generated time does not match the original length." +
                "  Corruption would result.");
        }

        out.write(newEncodedTime);
        hasher.update(newEncodedTime, 0, newEncodedTime.length);
    }

    protected int echoTag(OutputStream out) throws IOException {
        return echoTag(out, null);
    }

    protected int echoTag(OutputStream out, AtomicInteger i) throws IOException {
        int tag = readTag(crlIn, i);
        int tagNo = readTagNumber(crlIn, tag, i);
        out.write(rebuildTag(tag, tagNo));
        hasher.update(new Integer(tag).byteValue());
        return tagNo;
    }

    protected int echoLength(OutputStream out) throws IOException {
        return echoLength(out, null);
    }

    protected int echoLength(OutputStream out, AtomicInteger i) throws IOException {
        int length = readLength(crlIn, i);
        writeLength(out, length);
        hasher.update(new Integer(length).byteValue());
        return length;
    }

    protected int inflateLength(OutputStream out, int addedLength) throws IOException {
        int length = readLength(crlIn, null) + addedLength;
        writeLength(out, length);
        hasher.update(new Integer(length).byteValue());
        return length;
    }

    protected void echoValue(OutputStream out, int length) throws IOException {
        echoValue(out, length, null);
    }

    protected void echoValue(OutputStream out, int length, AtomicInteger i) throws IOException {
        byte[] item = new byte[length];
        readFullyAndTrack(crlIn, item, i);
        out.write(item);
        hasher.update(item, 0, item.length);
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
            throw new CryptoException("Cannot recognize digest.");
        }

        return dig;
    }
}
