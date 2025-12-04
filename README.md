# Hydrangea


This repository contains the reference implementation of [Hydrangea](https://eprint.iacr.org/2025/1112.pdf). The codebase is designed to be lightweight, efficient, and easy to modify or benchmark, but it is not intended for production deployment.

## Quick Start

The consensus protocols are implemented in Rust, while benchmarking scripts are written in Python and executed using [Fabric](http://www.fabfile.org/). 

To deploy and benchmark a 15-node local testbed, clone the repository and install the Python dependencies:

```
$ git clone https://github.com/nibeshrestha/hydrangea.git
$ cd hydrangea/benchmark
$ pip install -r requirements.txt
```
You will also need Clang (required for RocksDB) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux)
 (used to run all nodes and clients in the background). Once installed, you can launch a local benchmark using Fabric:

```
$ fab local
```

The first execution may take longer, as it compiles the Rust code in `release` mode. You can customize various benchmarking parameters in fabfile.py before running. Once the benchmark completes, a summary of the execution will be printed, similar to the example shown below.

```
-----------------------------------------
 SUMMARY:
-----------------------------------------
Logs generated at: 2025-12-04 16:18:20.302969

 + CONFIG:
 Consensus run in isolation
 Leader elector: Simple
 Faults: 0 node(s)
 Committee size: 15 node(s)
 F: 2
 C: 2
 K: 4

 Block size: 10 Certificates
 Timeout delay: 100 ms
 Sync retry delay: 5,000 ms
 Sync retry nodes: 3 node(s)

 + RESULTS:
 Execution time: 20 s
 Block Proposal time : 13 ms

 Block Commit:
   To First Commit:
     Mean Latency: 11 ms
     Median Latency: 11 ms
     BLPS: 76 blocks/s
   To Last Commit:
     Mean Latency: 16 ms
     Median Latency: 15 ms
     BLPS: 76 blocks/s
   Total Blocks Committed: 1,535
-----------------------------------------
```

## License

This software is licensed as [Apache 2.0](LICENSE).