# AVX Credential Generator

AVX Credential Generator is a tool for generation login credentials for Assembly Voting X.

## Prerequisites
```
$ bundle install
```

## Use case
Reads a csv file and generate credential pairs for each entry of the file. Generates two new files with the initial
content plus an extra column for election code or public key, respectively. The outputted files are located in /outputs.
The following command takes as arguments:
    - the path to the csv file
   ```
   $ bundler exec bin/avx_credential_generator generate_in_file file_path
   ```
