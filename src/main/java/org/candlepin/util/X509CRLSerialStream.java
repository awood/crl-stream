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

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.util.io.Streams;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Iterator;


/**
 * Reads an X509 CRL in a stream and returns the serial number for a revoked certificate
 * with each call to the iterator's next() function.
 *
 * The schema for an X509 CRL is described in
 * <a href="https://tools.ietf.org/html/rfc5280#section-5">section 5 of RFC 5280</a>
 *
 * It is reproduced here for quick reference
 *
 * <pre>
 * {@code
 * CertificateList  ::=  SEQUENCE  {
 *      tbsCertList          TBSCertList,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 *
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, MUST be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                    -- if present, version MUST be v2
 *                                }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                    -- if present, version MUST be v2
 *                                }
 *
 * Version, Time, CertificateSerialNumber, and Extensions
 * are all defined in the ASN.1 in Section 4.1
 *
 * AlgorithmIdentifier is defined in Section 4.1.1.2
 * }
 * </pre>
 *
 * ASN1 is based around the TLV (tag, length, value) concept.  Any piece of
 * data begins with a tag defining the data type, has a series of bytes to
 * indicate the data length, and then the data itself.
 *
 * See https://en.wikipedia.org/wiki/X.690 and http://luca.ntop.org/Teaching/Appunti/asn1.html
 * for reference on ASN1 and DER encoding.
 */
public class X509CRLSerialStream implements Closeable, Iterator<BigInteger> {
    private InputStream crlStream;

    // TODO should be a BigInteger?  Apparently long definite lengths can go up to 2^1008 - 1
    private Integer revokedSeqBytesLeft;

    /**
     * Construct a X509CRLStream.  <b>The underlying data in the stream parameter must
     * be in DER format</b>.  PEM format will not work because we need to operate
     * on the raw ASN1 of the DER.  Use Apache Common's Base64InputStream with the X509
     * header and footers stripped off if you need to use a PEM file.
     *
     * @param stream
     * @throws IOException if we can't read the provided File
     */
    public X509CRLSerialStream(InputStream stream) throws IOException {
        crlStream = stream;
        revokedSeqBytesLeft = discardHeader(crlStream);
    }

    /**
     * Construct a X509CRLStream.  <b>The crlFile parameter must be in DER format</b>.
     * PEM format will not work because we need to operate on the raw ASN1 of the DER.
     *
     * @param crlFile
     * @throws IOException if we can't read the provided File
     */
    public X509CRLSerialStream(File crlFile) throws IOException {
        this(new BufferedInputStream(new FileInputStream(crlFile)));
    }

    /**
     * Strip off the CRL meta-data and drill down to the sequence containing the
     * revokedCertificates objects.
     *
     * @return the length in bytes of the revokedCertificates sequence
     * @throws IOException
     */
    protected int discardHeader(InputStream s) throws IOException {
        // Strip the tag and length of the CertificateList sequence
        int tag = readTag(s);
        readTagNumber(s, tag);
        readLength(s);

        // At this point we are at the tag for the TBSCertList sequence and we need to
        // strip off the tag and length
        tag = readTag(s);
        readTagNumber(s, tag);
        readLength(s);

        // Now we are actually at the values within the TBSCertList sequence.
        // Read the CRL metadata and trash it.  We get to the thisUpdate item
        // and then break out.
        int tagNo = DERTags.NULL;
        while (true) {
            tag = readTag(s);
            tagNo = readTagNumber(s, tag);
            int length = readLength(s);
            byte[] item = new byte[length];
            readFullyAndTrack(s, item);

            if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
                break;
            }
        }

        tag = readTag(s);
        tagNo = readTagNumber(s, tag);

        // The nextUpdate item is optional.  If it's there, we trash it.
        if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
            int length = readLength(s);
            byte[] item = new byte[length];
            readFullyAndTrack(s, item);
            tag = readTag(s);
            tagNo = readTagNumber(s, tag);
        }

        // Return the length of the revokedCertificates sequence.  We need to
        // track the bytes we read and read no more than this length to prevent
        // decoding errors.
        return readLength(s);
    }

    public BigInteger next() {
        ASN1InputStream asn1In = null;

        try {
            // Strip the tag for the revokedCertificate entry
            int tag = readTag(crlStream);
            readTagNumber(crlStream, tag);

            int entryLength = readLength(crlStream);

            byte[] entry = new byte[entryLength];
            readFullyAndTrack(crlStream, entry);

            /* If we need access to all the pieces of the revokedCertificate sequence
             * we would need to rebuilt the sequence since we've already stripped off
             * the tag and length.  The code to do so is below.

             * ByteArrayOutputStream reconstructed = new ByteArrayOutputStream();
             * // An ASN1 SEQUENCE tag is 0x30
             * reconstructed.write(0x30);
             * reconstructed.write(entryLength);
             * reconstructed.write(entry);
             * ASN1InputStream asn1In = new ASN1InputStream(reconstructed.toByteArray());
             * ASN1Sequence obj = (ASN1Sequence) asn1In.readObject();
             * String s = ASN1Dump.dumpAsString(obj.getObjectAt(0));
             * asn1In.close();
             */

            /* Right now we are only using the serial number which is first in
             * the revokedCertificate sequence.  So all we need to do is read the next
             * TLV.  All the extra stuff in the entry byte array will just be ignored.
             */
            asn1In = new ASN1InputStream(entry);
            ASN1Integer serial = (ASN1Integer) asn1In.readObject();

            return serial.getValue();
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            if (asn1In != null) {
                IOUtils.closeQuietly(asn1In);
            }
        }
    }

    public boolean hasNext() {
        return revokedSeqBytesLeft > 0;
    }

    @Override
    public void close() throws IOException {
        crlStream.close();
    }

    /**
     * Read exactly the number of bytes equal to the length of the bytes parameter and
     * decrement the field holding the length of the revokedCertificate sequence accordingly.
     *
     * @param s the stream to read from
     * @param bytes the byte array to fill
     * @throws IOException if the stream cannot provide the number of required bytes
     */
    protected void readFullyAndTrack(InputStream s, byte[]  bytes) throws IOException {
        if (Streams.readFully(s, bytes) != bytes.length) {
            throw new EOFException("EOF encountered in middle of object");
        }

        if (revokedSeqBytesLeft != null) {
            revokedSeqBytesLeft -= bytes.length;
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
        if (revokedSeqBytesLeft != null) {
            revokedSeqBytesLeft--;
        }
        return i;
    }

    /**
     * The tag is the first byte of an ASN1 TLV group.  The tag specifies the
     * data type.  A tag can span multiple bytes but we have to examine the first
     * byte to determine if it does.
     *
     * This code is a slightly adapted version of the code in BouncyCastle's
     * ASN1InputStream.
     *
     * @param s an InputStream to read
     * @return an integer representing the first byte of the tag
     * @throws IOException
     */
    protected int readTag(InputStream s) throws IOException {
        int tag = readAndTrack(s);
        if (tag <= 0) {
            if (tag == 0)
            {
                throw new IOException("unexpected end-of-contents marker");
            }

            throw new IOException("negative tag value");
        }
        return tag;
    }

    /**
     * Read the tag value out of the tag byte and/or consume extra bytes
     * if the tag spans multiple octets.
     *
     * A tag is a single byte with the first 2 bits representing
     * the tag class (Universal, Application, etc) and the third bit
     * representing if the tag is primitive or constructed (meaning it
     * holds other tags within it).  The last 5 bits determine the data
     * type.  If the tag value is greater than 30, it won't fit in 5 bits
     * and the value 0b11111 is reserved to indicate that.  The tag is then
     * encoded in subsequent octets.
     *
     * See https://en.wikipedia.org/wiki/X.690#Identifier_octets
     *
     * This code is a slightly adapted version of the code in BouncyCastle's
     * ASN1InputStream.
     *
     * @param s an InputStream to read
     * @param tag the first byte of the tag
     * @return an integer representing the entire tag value
     * @throws IOException
     */
    protected int readTagNumber(InputStream s, int tag) throws IOException {
        int tagNo = tag & 0x1f;

        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = readAndTrack(s);

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            // Note: -1 will pass
            if ((b & 0x7f) == 0) {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0)) {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = readAndTrack(s);
            }

            if (b < 0) {
                throw new EOFException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
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
