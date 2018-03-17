### Mongo Mover

* Dump Mongo database and write AES encrypted output to a zip file.

`./mongo-mover.py -s localhost -db arc -key ch33s3 -salt mysalt -ez exported.zip`

* Decrypt an exported zip file to a destination directory.

`./mongo-mover.py -ez exported.zip -key ch33s3 -salt mysalt
