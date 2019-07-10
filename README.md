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

3. Combine multiple public key files into one main public key file. The input files are the ones received from each
credential authority. The output public key file is the one that needs to be imported into the AVX system. The outputted
file is located in /outputs.
The script has an interactive behaviour and the user needs to specify the column used as the voter identifier. The user
also needs to specify the name of the output file.
The script expects that all input files have the same data structure (csv files have the same columns) and that the data
from all files is consistent (the identifier column is identical in all files).
The following command takes as arguments:
   - a list of all the paths to the public key files, separated by space
   ```
   $ bundler exec bin/avx_credential_generator group_public_key_files file1_path file2_path file3_path
   ```
