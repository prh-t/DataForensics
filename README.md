# Data Forensics

This is a simple disk investigating tool written in Python 3.6, it's an assignment for a university module. 


## Desc

This tool assumes that a disk image file "example.dd" with a standard MBR is to be examined, once the examination is done, it prints out the following information about the disk image: 

* Number of partitions on the disk, and for each partition: 
    * Partition type, 
    * Starting sector, 
    * Partition size in sectors. 
* For a FAT16 partition: 
    * Number of sectors per cluster, 
    * size of the FAT area, 
    * size of the Root directory, 
    * sector address of cluster no.2, 
    * some detailed information about the first deleted file in this partition.
* For an NTFS partition: 
    * Number of bytes per sector, 
    * number of sectors per cluster, 
    * sector address of the $MFT record, 
    * Type and length of the first two attributes in $MFT.


## Misc 
A disk image file can be created using [FTK imager](https://accessdata.com/product-download/ftk-imager-version-4-5), which can also be used to explore raw data on a hard disk.
