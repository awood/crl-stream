# Introduction
X509CRLEntryStream is a class for rapidly reading an X509 certificate revocation
list and pulling out the serial numbers from it.  Most CRL implementations read
the entire list into memory which can be problematic for exceptionally large
CRLs.

X509CRLEntryStream parses the underlying ASN1 of a CRL and descends to the
certificate entries list.  From there it iterates over the list pulling out each
entry's serial number.

If you are reading a large CRL, you may also want to write to it.
X509CRLStreamWriter is my solution to that problem.  It moves through the ASN1
and adds entries you provide at the end of the list.  Then it signs the new CRL
with a RSA private key you provide.

If you want to delete items from a CRL, you can use X509CRLStreamWriter and pass
it an instance of CRLEntryValidator.  The CRLEntryValidator is a callback that
has its `shouldDelete` method invoked for every existing entry.  The
`shouldDelete` method receives an X509CRLEntryObject and returns true if the
entry in question should be deleted.

Deleting items is slightly more expensive computationally because we have to do
a double pass over the CRL.  Once to find and collect the entries to delete and
once to rebuild the CRL.

# Warnings
X509CRLEntryStream does not perform any signature checking on the CRL.
Therefore it is **wholly inappropriate** to use it for a CRL that you do not
control yourself or otherwise trust implicity.

X509CRLEntryStream can only operate on DER encoded CRLs.  Re-encoding a PEM
encoded CRL can be done with openssl:

```
openssl -in my_pem_crl.pem -inform pem -out my_der_crl.der -outform der
```

Or you can use Commons Codec's Base64InputStream to send in PEM although you
**must** remove the `----BEGIN X509 CRL-----` and `-----END X509 CRL-----`
header and footer.

Currently X509CRLStreamWriter does not provide a way to set an arbitrary
nextUpdate time on a CRL.  Instead it moves the nextUpdate time forward by the
same delta the original nextUpdate was from the original thisUpdate time.

# Results
The performance difference between X509CRLStreamWriter and CertificateFactory,
the standard Java CRL parsing class, is dramatic in both memory usage and
execution time.

## Execution Time
These benchmarks use a CRL with 2 million entries.

```
Benchmark                   Mode  Cnt      Score      Error  Units
CRLBenchmark.inMemory       avgt   20   7069.805 ±  911.482  ms/op
CRLBenchmark.stream         avgt   20    588.389 ±   40.294  ms/op
CRLWriteBenchmark.inMemory  avgt   20  12489.203 ± 1107.244  ms/op
CRLWriteBenchmark.stream    avgt   20   1218.187 ±  530.333  ms/op
```

## Memory Use
Benchmark      | Full GC Pauses | GC Pauses | Total Heap
-------------- | -------------- | --------- | ----------
Serial Stream  | 4              | 220       | 1,599M
Serial InMemory| 33             | 97        | 2,275M
Write Stream   | 3              | 30        | 1,346M
Write InMemory | 48             | 603       | 2,353M

# Running the Benchmarks Yourself
```
$ mvn clean package
$ java -jar target/benchmarks.jar
```

The JMH benchmarking toolkit creates the benchmarks.jar file and running it with
the `-h` option will reveal a wealth of options on how many iterations to
perform, how many warm-up iterations to run, etc.
