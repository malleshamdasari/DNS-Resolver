********************************************************************************
*************************** README of FCN Homework1 ****************************
********************************************************************************

This folder contains the following:
===================================

	* Source code
		- Mydig-PartA.py (My Resolver)
                - Mydig-PartB.py (My Resolver with dnssec)
        * Report.pdf
                - Contains the part C i.e, CDF result and explanation
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
