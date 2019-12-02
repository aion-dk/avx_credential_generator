require 'thor'
require 'crypto/crypto'
require 'helpers/application_helper'

module AVXCredentialGenerator
  class Main < Thor
    include AVXCredentialGenerator::ApplicationHelper

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

      say("Done! Outputted files:\n#{ec_absolute_path}\n#{pk_absolute_path}")
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
