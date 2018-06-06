PoSeidon
========

Overview
--------
This folder contains a bunch of tools and analysis on POS malware PoSeidon.

Configuration Data
------------------
Configuration data is embedded in the malware. This can be seen in PoSDecrypt.

Resolving DLLs
--------------
Hashing of function name and dll name has also been reverse-engineered and a
python implementation has been provided.
The hashing function used is the Jenkins' one_at_a_time function:
https://en.wikipedia.org/wiki/Jenkins_hash_function


Lloyd Macrohon <jl.macrohon@gmail.com>

