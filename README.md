# Byzcrash and Jolteon*

This branch contains a reference implementation of Byzcrash and Jolteon* consensus protocol under failure evaluated in the [Hydrangea](https://eprint.iacr.org/2025/1112.pdf) paper.

Both protocols share the same core implementation (only the fault-tolerance parameters differ).

To configure ByzCrash, set the desired crash-fault parameter $c$ in the `node_params` within the local or remote benchmark functions in benchmark/fabfile.py. For Jolteon$^*$, set c=0.
