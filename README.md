# Fingerprint Recognition System with Homomorphic Encryption

This repository implements a secure fingerprint matching and verification system using Paillier Homomorphic Encryption. It allows templates to be stored and compared securely, preserving user privacy.

## Features

- Paillier Homomorphic Encryption: Key generation, encryption, and decryption of minutiae templates using the Paillier cryptosystem.
- Geometric Alignment: Automatically computes rotation and translation alignment parameters between source and target minutiae sets using numerical optimization.
- Secure Matching: Performs comparison between encrypted queries and stored templates using Kd-Tree spatial query indexes and orientation differences.
- Performance Evaluation: Evaluates overall verification accuracy with False Accept Rate (FAR), False Reject Rate (FRR), Equal Error Rate (EER), and threshold plotting.

## Dataset

The included `dataset` folder contains fingerprint impressions from FVC2004 DB2-A:
- `dat`: Original fingerprint image data files.
- `txt`: Extracted minutiae coordinate matrices (each file contains rows of `x`, `y`, and `angle` values).

### Naming Convention and Matching Logic
Files are named in the format `X_Y.txt` where:
- `X` represents the Subject ID (indicating fingerprints belonging to the same person and the same finger/hand).
- `Y` represents the Impression ID (various sample impressions 1 through 8 taken from the same finger/hand).

Impressions with the same prefix `X_` are evaluated as **genuine matches**, while impressions with different `X_` prefixes are evaluated as **imposter matches** to evaluate false accept and false reject rates (FAR/FRR).

## Dependencies

- numpy
- scipy
- phe (Paillier Homomorphic Encryption)
- matplotlib

## Execution

Ensure all dependencies are installed:

```bash
pip install numpy scipy phe matplotlib
```

Open and run the Jupyter notebook (`FFD_IDP.ipynb`) to load the dataset, perform secure matching, and plot metrics.
