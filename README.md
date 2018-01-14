# PAN_reporter
Simple (and probably very dirty) python script for pulling reports from PAN Firewall
The script is using Python 3 library.

## Usage:

The script will run through the current working directory from where the script was run and iterate through the configuration files, this allows for multiple different report jobs to be run against different firewalls if necessary.

Make a copy of the `'config.conf.sample'` file and edit as required.
You can have multiple config files as long as the file extension is `.conf`.

You will need your API key from the firewall,
`https://<firewall>/api/?type=keygen&user=<username>&password=<password>` and the names of the reports that you would like to run.

#### TODO:

* Exception handling (there is currently no error checking so if there is an error the script will break)
* Report filtering (automatically build the required report list based on text filter)
##### Long term.
* Report writing (A framework to build a customised report with all the required info, graphing etc.)
