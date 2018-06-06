Overview
========

poseidon.py contains the hashing functions used by PoSeidon to resolve dlls and
function names.

The resolved names are stored in fn-hash.csv for reference. An IDA scrypt can
also be used to resolve the hash ids to its name and dll in IDA to facilitate
reverse engineering.

IDA Pro Plugin
--------------

Also added a file called ida-poseidon.py that allows you to view and import the
hashes into IDA pro.
![ida window](https://raw.githubusercontent.com/bizdak/PoSeidon/master/python/ida-window.png)

This allows you to assign meaningful names to the hashes, e.g.
![ida enum](https://raw.githubusercontent.com/bizdak/PoSeidon/master/python/ida-window-assign-enum.png)

Unfortunately, IDA enums are only 32-bits, while the hashes are 64-bits. Luckily
there are only a few collisions (81 out of 5714 of all exports in referenced dlls).
So this is still a huge benefit to the reverse engineer.


Lloyd Macrohon <jl.macrohon@gmail.com>

