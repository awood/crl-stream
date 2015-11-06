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

import static org.candlepin.util.DERUtil.*;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERTags;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;


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
    private Integer revokedSeqBytes;
    private AtomicInteger count;

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
        revokedSeqBytes = discardHeader(crlStream);
        count = new AtomicInteger();
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
        int tag = readTag(s, count);
        readTagNumber(s, tag, count);
        readLength(s, count);

        // At this point we are at the tag for the TBSCertList sequence and we need to
        // strip off the tag and length
        tag = readTag(s, count);
        readTagNumber(s, tag, count);
        readLength(s, count);

        // Now we are actually at the values within the TBSCertList sequence.
        // Read the CRL metadata and trash it.  We get to the thisUpdate item
        // and then break out.
        int tagNo = DERTags.NULL;
        while (true) {
            tag = readTag(s, count);
            tagNo = readTagNumber(s, tag, count);
            int length = readLength(s, count);
            byte[] item = new byte[length];
            readFullyAndTrack(s, item, count);

            if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
                break;
            }
        }

        tag = readTag(s, count);
        tagNo = readTagNumber(s, tag, count);

        // The nextUpdate item is optional.  If it's there, we trash it.
        if (tagNo == DERTags.GENERALIZED_TIME || tagNo == DERTags.UTC_TIME) {
            int length = readLength(s, count);
            byte[] item = new byte[length];
            readFullyAndTrack(s, item, count);
            tag = readTag(s, count);
            tagNo = readTagNumber(s, tag, count);
        }

        // Return the length of the revokedCertificates sequence.  We need to
        // track the bytes we read and read no more than this length to prevent
        // decoding errors.
        return readLength(s, count);
    }

    public BigInteger next() {
        ASN1InputStream asn1In = null;

        try {
            // Strip the tag for the revokedCertificate entry
            int tag = readTag(crlStream, count);
            readTagNumber(crlStream, tag, count);

            int entryLength = readLength(crlStream, count);

            byte[] entry = new byte[entryLength];
            readFullyAndTrack(crlStream, entry, count);

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
        return revokedSeqBytes > count.get();
    }

    @Override
    public void close() throws IOException {
        crlStream.close();
    }
}
