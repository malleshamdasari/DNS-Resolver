********************************************************************************
************************ README on DNSResolver in Python ***********************
********************************************************************************

This folder contains the following:
===================================

	* Source code
		- MyDigDNS.py (My Resolver)
                - MyDigDNSSEC.py (My Resolver with dnssec)
	* mydig_output.txt
		- Contains the output of A, NS, MX types for top 25 websites

Compilation and Running:
=======================
* Dependencies
	- Python 2.7 or 3.x Later
	- Install the dnspython and pycrypto
* Running the code 
	$ python mydig [Domain Name] [Resource Record type]
* Examples
	$ python mydig google.com A
	$ python mydig facebook.com NS
	$ python mydig stonybrook.edu MX

Notes:
======
	
	* The test cases, sample intputs and outputs are given in Report.pdf
