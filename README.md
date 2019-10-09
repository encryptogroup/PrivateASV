## Implementation of "Privacy-Preserving PLDA Speaker Verification using Outsourced Secure Computation"
#### by *Amos Treiber* ([ENCRYPTO](https://encrypto.de), TU Darmstadt), *Andreas Nautsch* ([EURECOM](http://www.eurecom.fr/en/research/networking-and-security-department)), *Jascha Kolberg* ([da/sec](https://dasec.h-da.de), Hochschule Darmstadt), *Thomas Schneider* ([ENCRYPTO](https://encrypto.de), TU Darmstadt), and *Christoph Busch* ([da/sec](https://dasec.h-da.de), Hochschule Darmstadt) ([Online Edition](http://dx.doi.org/10.1016/j.specom.2019.09.004) & [PDF](https://encrypto.de/papers/TNKSB19.pdf))

----

### About
This code provides circuit descriptions and a testing environment to evaluate the biometric performance as well as runtime benchmarks for PLDA speaker verification using the [ABY](https://github.com/encryptogroup/ABY) framework. This is an experimental research prototype to evaluate benchmarks and not intended for real-world deployment. We make no guarantees about its security and correctness.

### Requirements and Installation
This code requires all [ABY](https://github.com/encryptogroup/ABY) requirements and can be set up and executed like any other ABY example.

### Parameters
```Usage: ./asv_test
 -r [Role: 0/1, required]
 -b [Bit-length, default 64, optional]
 -n [Number of elements of an i-vector (has to be 50, 100, 150, 200, 250, 400, 600), optional]
 -s [Symmetric Security Bits, default: 128, optional]
 -a [IP-address, default: localhost, optional]
 -p [Port, default: 7766, optional]
 -d [Distance used for verification, 0=EUCLIDEAN, 1=COSINE, 2=HAMMING, 3=TWOCov/non-centered PLDA, 4=centered PLDA, default: 1, optional]
 -f [bit indicating whether the operations should be floating point, 0=INT, 1=FLOAT, default: 0, optional]
 -i [Number of iterations for benchmarking, default: 1, optional]
 -m [Mode of operation, 0: benchmarking i-vector challenge data over i samples, 1: unlinkability of i-vector challenge data over the first i samples (store shares Y2 & Z2 (score)), 2: biometric performance of i-vector challenge data over first i combinations of the comparisons file (store score & decision), 3: use random values and benchmark i iterations, 4: plain biometric performance of i-vector challenge data over first i combinations of the comparisons file (log score & decision) in plaintext, default: 0 , optional, optional]
 -t [64-bit INT threshold for verif., has to be given as an int, default: log(99) *10^5, optional]
 -j [Comparison file name, default=comparisons, optional]
 -c [PLDA Subspace dimension, default: 25, optional]
 -g [Use Yao's GC for the entire computation (only possible if floats are used), default=0, optional]
```

### Reproduction of Results
* For reproducing benchmarks, select mode 3 (using random data).
* For evaluating the biometric performance of the i-vector challenge data, the data has to be provided following way (in the build folder where the executables are):
  - Filename `referencesN`, where `N in {50, 100, 150, 200, 250, 400, 600}` denotes the dimension of the vector. Each line has to look like this: `speakerID,y[1] y[2] ... y[N]`, where `speakerID` is a string, and each `y[i]` is a 32-bit float.
  - Filename `probesN`, where `N in {50, 100, 150, 200, 250, 400, 600}` denotes the dimension of the vector. Each line has to look like this: `probeID,x[1] x[2] ... x[N]`, where `probeID` is a string, and each `x[i]` is a 32-bit float.
  - Filename `comparisons` (can be specified via the `-f` flag) denotes which speakers shall be compared to which probes. Each line has to look like this: `speakerID,probeID`, where `speakerID` and `probeID` are strings.
* For PLDA/2Cov, additional model data has to be provided in the following way:
  - Non-centered PLDA/2Cov:
    - Filename `kN`, where `N in {50, 100, 150, 200, 250, 400, 600}`, provides one float value.
    - Filename `cN`, where `N in {50, 100, 150, 200, 250, 400, 600}`, contains one float value per line.
    - Filename `LN`, where `N in {50, 100, 150, 200, 250, 400, 600}`, each of the `N` lines contains `N` float values, speparated by spaces.
    - Filename `GN`, where `N in {50, 100, 150, 200, 250, 400, 600}`, each of the `N` lines contain `N` float values, speparated by spaces.

  - Centered PLDA/2Cov (used for PLDA biometric accuracy reporting):
    - Filename `PLDA_kN_s`, where `N in {50, 100, 150, 200, 250, 400, 600}` and `s` is the subspace dimension (int), provides one float value.
    - Filename `PLDA_QN_s`, where `N in {50, 100, 150, 200, 250, 400, 600}` and `s` is the subspace dimension (int), each line contains `N` float values, speparated by commas.
    - Filename `PLDA_PN_s`, where `N in {50, 100, 150, 200, 250, 400, 600}` and `s` is the subspace dimension (int), each line contains `N` float values, speparated by commas.
* Except for Mode 4, two instances of `asv_test` are run, one as `P0` (`-r 0`) and one as `P1` (`-r 1`). `P0` needs access to the vector & model files.
* Outputs: 
  - Mode 0: authentication correctness, time & communication on provided data.
  - Mode 1: files (`YPA, YPB, ZPA, ZPB`) => use for unlinkability analysis, unreliable for benchmarking!
  - Mode 2: file `scores_and_decisions` => use for biometric performance analysis, unreliable for benchmarking!
  - Mode 3: correctness, time & communication on random data.
  - Mode 4: file `scores_and_decisions` => use for plaintext biometric performance analysis.

### Required Pre-processing
* Cosine score: provide `x` and `y` normalized: `referenceVector = y/||y||, probeVector = x/||x||`.
* PLDA & 2Cov score: Model has to already be computed.

### Examples (on localhost)
* Run cosine distance on 600-dimensional i-vectors specified by the 50 first comparisons of the i-vector challenge (files need to be provided - see above), mode: save resulting distances & decisions (biometric performance use case):

  Party/Terminal 0: `./asv_test -r 0 -d 1 -n 600 -m 2 -i 50`

  Party/Terminal 1: `./asv_test -r 1 -d 1 -n 600 -m 2 -i 50`

* Run non-centered PLDA/2Cov score on 250-dim i-vectors specified by the 10 first comparisons of the i-vector challenge (files need to be provided - see above), mode: save resulting Y and Z shares across two different applications (unlinkability analysis use case):
 
  Party/Terminal 0: `./asv_test -r 0 -d 3 -n 250 -m 1`

  Party/Terminal 1: `./asv_test -r 1 -d 3 -n 250 -m 1`

* Run centered PLDA/2Cov score on 250-dim i-vectors specified by the 100 first comparisons of the i-vector challenge with a PLDA model using subspace 50 (files need to be provided - see above) using `t=0.5` as threshold, mode: output mean communication bytes and time (benchmarking use case):
 
  Party/Terminal 0: `./asv_test -r 0 -d 4 -n 250 -m 0 -i 100 -t 50000 -c 50`
 
  Party/Terminal 1: `./asv_test -r 1 -d 4 -n 250 -m 0 -i 100 -t 50000 -c 50`

### Issues & Notes
- The evaluation of `#errors` that are reported only depends on the threshold decision bit, meaning only correctness of the decision is checked, not correctness of the score computation. The computation of the scores is only explicitly verified and reported in the Biometric Performance modes (Modes 1 & 2).
- Using only Yao's GC for the floating point computation can result in incorrect scores.
- The flag `-b 32` is only intended for runtime benchmarking (and not accuracy evaluation) with 32-bit precision.
