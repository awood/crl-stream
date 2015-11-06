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

import org.bouncycastle.util.io.Streams;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicInteger;

public class DERUtil {

    private DERUtil() {
        // No instances allowed
    }

    /**
     * Read exactly the number of bytes equal to the length of the bytes parameter and
     * increase the counter accordingly.
     *
     * @param s the stream to read from
     * @param bytes the byte array to fill
     * @param count the counter to modify.  Can be null.
     * @throws IOException if the stream cannot provide the number of required bytes
     */
    public static void readFullyAndTrack(InputStream s, byte[] bytes, AtomicInteger count) throws IOException {
        if (Streams.readFully(s, bytes) != bytes.length) {
            throw new EOFException("EOF encountered in middle of object");
        }

        if (count != null) {
            count.addAndGet(bytes.length);
        }
    }

    /**
     * Read a single byte and increment the counter.
     *
     * @param s the stream to read from
     * @param count the counter to increment.  Can be null.
     * @return an integer representing the byte read.
     * @throws IOException
     */
    public static int readAndTrack(InputStream s, AtomicInteger count) throws IOException {
        int i = s.read();
        if ( count != null) {
            count.incrementAndGet();
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
     * @param count the counter to modify.  Can be null.
     * @return an integer representing the first byte of the tag
     * @throws IOException
     */
    public static int readTag(InputStream s, AtomicInteger count) throws IOException {
        int tag = readAndTrack(s, count);
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
     * @param count the counter to modify.  Can be null.
     * @return an integer representing the entire tag value
     * @throws IOException
     */
    public static int readTagNumber(InputStream s, int tag, AtomicInteger count) throws IOException {
        int tagNo = tag & 0x1f;

        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = readAndTrack(s, count);

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            // Note: -1 will pass
            if ((b & 0x7f) == 0) {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0)) {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = readAndTrack(s, count);
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
     * @param s the InputStream to read from
     * @param count the counter to modify.  Can be null.
     * @return
     * @throws IOException
     */
    public static int readLength(InputStream s, AtomicInteger count) throws IOException {
        int length = readAndTrack(s, count);
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
                int next = readAndTrack(s, count);

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

    /**
     * Write an integer as a DER encoded definite length.
     *
     * @param out
     * @param length
     * @throws IOException
     */
    public static void writeLength(OutputStream out, int length) throws IOException {
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

    public static int rebuildTag(int tag, int tagNo) {
        // FIXME this code is assuming a 1 byte tag
        return tag;
    }
}
