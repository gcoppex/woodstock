# Woodstock

Woodstock is a simple [Certificate Transparency](https://www.certificate-transparency.org/) logs crawler. CT logs server are queried and the raw certificate data is extracted into CSV or Parquet files.

## Installation

To install Woodstock, clone this git repository and then use pip to install the program:

```python
pip3 install woodstock
```

The program requires python3.6 (or greater) and the dependencies can be installed by:

```
pip3 install -r requirements.txt
```

In case you want to export [parquet files](https://parquet.apache.org/), you might ne to install the snappy compression library:

```bash
apt-get install libsnappy-dev
```

On Windows, you can type:

```powershell
conda install -c conda-forge python-snappy
```

## Usage

To use Woodstock, you can type:

```
woodstock -o /tmp/output_dir/ -f parquet
```

Here is the full command details (using `woodstock --help`) :

```
Usage: woodstock.py [-h] [-o OUTPUT_DIR] [-f OUTPUT_FORMAT]

Crawler of Certificate " + "Transparency log servers (CT logs servers).

optional arguments:
  -h, --help        show this help message and exit
  -o OUTPUT_DIR     The path of the output directory (should end with a /)
  -f OUTPUT_FORMAT  The format of the output files
  -v VERBOSE        The verbosity of the output (can be True or False)

```

## Explaination of the download process

The program first queries the [Google CT log server list](https://www.gstatic.com/ct/log_list/log_list.json) and then queries each retrieved servers in parallel. For each server, 8 TCP requests are emitted in parallel, to amortize the RTT delay and maximize throughput.

Each raw certificate is extracted (see the fields below) and stored in a raw-based storage. CSV and Parquet files formats are currently supported.

### Automatic restarting of download
In case the download is interrupted or stopped by the user, Woodstock restarts at the offset, just after the last recorded chunk.

### Extracted fields

Here is the list of certificate fields that are output by Woodstock.

| Extracted field | Short description |
| --------------- | ------------- |
| cert_index            | The index of the certificate on a given CT log server      |
| server_url            | The CT log server URL      |
| serial_number         | CT log server generated serial number     |
| subject_org_name      | Organization name of the certificate subject |
| subject_org_unit_name | Unit name of the certificate subject      |
| subject_common_name   | Common name of the certificate subject      |
| subject_country       | Country of the certificate subject      |
| subject_province      | Province of the certificate subject       |
| subject_locality      | Locality of the certificate subject       |
| issuer_org_name       | Name of the certificate issuer       |
| issuer_org_unit_name  | Organization name of the certificate issuer |
| issuer_common_name    | Common name of the certificate issuer      |
| issuer_country        | Country of the certificate issuer      |
| issuer_province       | Province of the certificate issuer      |
| issuer_locality       | Locality of the certificate issuer      |
| extensions            | A json string containing certificate extensions  |
| cert_type             | Type of certificate      |
| signature_algorithm   | Signature algorithm name      |
| key_size              | Size of the key      |
| timestamp             | timestamp of the certificate      |
| chain_hash            | CT log chain_hash      |
| not_before            | Certificate start validity timestamp      |
| not_after             | Certificate end validity timestamp      |

### Extracted record size

Depending on the output format, the extracted record size varies as follow:

    Parquet file : approx. 0.625 KB / extracted record
    CSV file : approx. 1.6 KB / extracted record
### License

This program is distributed under the MIT License (read LICENSE.txt)

> ```
>  ...
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>  ...
> ```

### Acknowledgments

Thanks to [@jojolebarjos](https://github.com/jojolebarjos) and [@nsanglar](https://github.com/nsanglar) for the ideas and code review. Thanks to https://github.com/CaliDog/Axeman for the datastructure approach idea.
