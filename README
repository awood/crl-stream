# Introduction
X509CRLSerialStream is a class for rapidly reading an X509 certificate revocation list and pulling out the serial numbers from it.  Most CRL implementations read the entire list into memory which can be problematic for exceptionally large CRLs.

X509CRLSerialStream parses the underlying ASN1 of a CRL and descends to the certificate entries list.  From there it iterates over the list pulling out
each entry's serial number.

If you are reading a large CRL, you may also want to write to it.  X509CRLStreamWriter is my solution to that problem.  It moves through the ASN1
and adds entries you provide at the end of the list.  Then it signs the new CRL with a RSA private key you provide.

# Warnings
X509CRLSerialStream does not perform any signature checking on the CRL.
Therefore it is **wholly inappropriate** to use it for a CRL that you do not
control yourself or otherwise trust implicity.

X509CRLSerialStream can only operate on DER encoded CRLs.  Re-encoding a PEM
encoded CRL can be done with openssl:

```
openssl -in my_pem_crl.pem -inform pem -out my_der_crl.der -outform der
```

Currently X509CRLStreamWriter does not update the timestamps on the CRL.

# Results
The performance difference between X509CRLStream and CertificateFactory, the
standard Java CRL parsing class, is dramatic in both memory usage and execution time.

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
