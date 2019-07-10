require 'thor'
require 'crypto/crypto'
require 'helpers/application_helper'

module AVXCredentialGenerator
  class Main < Thor
    include AVXCredentialGenerator::ApplicationHelper

    desc 'say_hello', 'Prints hello world'
    def say_hello
      puts 'hello world !'
    end

    desc 'generate n', 'Generate n pair of election codes - public keys'
    def generate(n)
      credential_pairs = generate_credential_pairs(n.to_i)

      credential_pairs.each do |election_code, public_key|
        $stdout.puts "#{election_code}\t#{public_key}"
      end
    end

    desc 'generate_in_file PATH', 'Generate election codes for each identifier form the file'
    def generate_in_file(path)
      headers, *rows = read_csv(File.read(path))

      credential_pairs = generate_credential_pairs(rows.size)

      basename = File.basename(path, '.csv')

      # generate election codes file
      rows_plus_election_codes = rows.zip(credential_pairs.keys).map{ |row, election_code| row + [election_code] }
      headers_plus_election_code = headers + ['Election code']
      ec_absolute_path = absolute_output_path("#{basename}_election_codes.csv")
      write_csv(ec_absolute_path, headers_plus_election_code, rows_plus_election_codes)

      # generate public keys file
      rows_plus_public_keys = rows.zip(credential_pairs.values).map{ |row, public_key| row + [public_key] }
      headers_plus_public_key = headers + ['Public key']
      pk_absolute_path = absolute_output_path("#{basename}_public_keys.csv")
      write_csv(pk_absolute_path, headers_plus_public_key, rows_plus_public_keys)

      $stdout.puts 'Outputted files:'
      $stdout.puts ec_absolute_path
      $stdout.puts pk_absolute_path
    end

    desc 'group_public_key_files FILE_PATHS', 'Group all public key files into one'
    def group_public_key_files(*paths)
      public_keys = {}

      paths_first, *paths_rest = paths
      file_headers, *file_rows = read_csv(File.read(paths_first))

      index = ask_identifier_header_from_file(file_headers)

      file_rows.each do |row|
        id = row[index]
        public_keys[id] = row.last
      end


      paths_rest.each do |path|
        headers, *rows = read_csv(File.read(path))

        rows.each do |row|
          id = row[index]
          public_key = row.last

          unless public_keys.key?(id)
            raise Thor::Error, 'Files are not consistent. Identifier column does not match across files'
          end

          public_keys[id] = Crypto.combine_public_keys(public_keys[id], public_key)
        end
      end



      file_rows.zip(public_keys.values).map do |row, public_key|
        # replace the old public key with the new computed one
        row[row.size - 1] = public_key
      end


      # write to file
      public_keys_file = ask_public_keys_path
      write_csv(public_keys_file, file_headers, file_rows)

      $stdout.puts 'Outputted files:'
      $stdout.puts public_keys_file
    end


    private

    def generate_credential_pairs(n)
      credential_pairs = {}

      n.times do
        # generate unique codes
        begin
          election_code, public_key = Crypto.generate_credential_pair
        end while credential_pairs.key?(election_code)

        credential_pairs[election_code] = public_key
      end

      credential_pairs
    end
  end
end
