# AVX Credential Generator

AVX Credential Generator is a tool for generation login credentials for Assembly Voting X.

## Prerequisites
```
$ bundle install
```

## Use cases
1. Generate n credential pairs, which consist of an election code and a public key. The credential pairs will be printed 
in the terminal. The following command takes as arguments:
   - n, the number of credential pairs
   ```
   $ bundler exec bin/avx_credential_generator generate n
   ```
    
2. Reads a csv file and generate credential pairs for each entry of the file. Generates two new files with the initial
content plus an extra column for election code or public key, respectively. The outputted files are located in /outputs.
The following command takes as arguments:
    - the path to the csv file
   ```
   $ bundler exec bin/avx_credential_generator generate_in_file file_path
   ```
