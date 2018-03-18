### Mongo Mover

* Dump Mongo database and write AES encrypted output to a zip file.

`./mongo-mover.py -s localhost -db arc -key ch33s3 -salt mysalt -ez exported.zip`

* Encrypt database backups on a schedule with intervals in seconds.

`./mongo-mover.py -s localhost -db arc -key ch33s3 -salt mysalt -ez exported.zip -schedule 86400`

* Decrypt an exported zip file.

`./mongo-mover.py -d -ez exported.zip -key ch33s3 -salt mysalt`
