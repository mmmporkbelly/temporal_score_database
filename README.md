# The Temporal Score Database
> [!NOTE]
> Check out the vulnerability decision tree if the temporal score database is useful

## What is the temporal score database?
The temporal score database is a python script that pulls data from NVD, MITRE, EPSS, Nuclei, ExploitDB, Github, and Metasploit to enrich CVSS data. The database provides a daily .xlsx file which pulls from the aforementioned sources, and calculates the temporal vector, score, and severity for all CVEs published by NVD or MITRE. This can be used as part of the vulnerability decision tree.

## Great! Can I use it? Do I have to edit it in any way?
This is an opensourced passion project - please feel free to use it in any capacity. NOTE: You will have to add in your AWS account number, S3 bucket name, etc, if you would like to use the code to its full capacity. If you would like to see specifically what information is included, check out the web app at: 
> [!CAUTION]
> This web app was only made to showcase the information that is possible to be pulled by this script.

## How can I view the data?
The recommended method is to build a container (docker file included in code) and run it on a daily basis. The code is currently formatted to support AWS services, including secrets manager and uploading/downloading to an S3 bucket.

## You mentioned secrets manager. Does it use any keys?
Yes, but only an NVD API key. That key is not necessary to actually pull the data, you will just be rate limited without it. 
