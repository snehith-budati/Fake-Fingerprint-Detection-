# Fingerprint Recognition System with Homomorphic Encryption

This repository implements a secure fingerprint matching and verification system using Paillier Homomorphic Encryption. It allows templates to be stored and compared securely, preserving user privacy.

## Features

- Paillier Homomorphic Encryption: Key generation, encryption, and decryption of minutiae templates using the Paillier cryptosystem.
- Minutiae Parsing: Reads coordinate points (x, y, angle) from standard text templates.
- Geometric Alignment: Automatically computes rotation and translation alignment parameters between source and target minutiae sets using numerical optimization.
- Secure Matching: Performs comparison between encrypted queries and stored templates using Kd-Tree spatial query indexes and orientation differences.
- Performance Evaluation: Evaluates overall verification accuracy with False Accept Rate (FAR), False Reject Rate (FRR), Equal Error Rate (EER), and threshold plotting.

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

Run the main Python script or open the Jupyter notebook (`FFD_IDP.ipynb`) to start the interactive program:

```bash
python fingerprint_system.py
```
