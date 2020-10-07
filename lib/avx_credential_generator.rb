require 'thor'
require 'crypto/crypto'
require 'helpers/application_helper'

module AVXCredentialGenerator
  class Main < Thor
    include AVXCredentialGenerator::ApplicationHelper

    desc 'generate PATH', 'Generate election codes and public keys for each identifier in the file'
    def generate(path)
      headers, *rows = read_csv(path)

      credential_pairs = generate_credential_pairs(rows.size)

      basename = File.basename(path, '.csv')

      # generate election codes file
      rows_plus_election_codes = rows.zip(credential_pairs.keys).map{ |row, election_code| row + [election_code] }
      headers_plus_election_code = headers + ['Election code']

      ec_absolute_path = ask_output_path('.csv', 'election_codes', 'Pick a name for the election codes file')
      output(ec_absolute_path) do |csv|
        csv << headers_plus_election_code
        rows_plus_election_codes.each{ |row| csv << row }
      end


      # generate public keys file
      rows_plus_public_keys = rows.zip(credential_pairs.values).map{ |row, public_key| row + [public_key] }
      headers_plus_public_key = headers + ['Public key']

      pk_absolute_path = ask_output_path('.csv', 'public_keys', 'Pick a name for the public keys file')
      output(pk_absolute_path) do |csv|
        csv << headers_plus_public_key
        rows_plus_public_keys.each{ |row| csv << row }
      end

      say("Done! Outputted files:\n#{ec_absolute_path}\n#{pk_absolute_path}")
    end

    desc 'compute PATH', 'Compute public keys for each identifier in the file, using as election codes a specific column'
    def compute(path)
      headers, *rows = read_csv(path)

      election_codes = []
      loop do
        index = ask_header_index(headers, 'What column to use as election codes?')
        column = rows.map{ |row| row[index] }

        # Error if there are empty values
        if column.any?{ |s| s.nil? || s.strip == ''}
          say("The column '#{headers[index]}' contains blank values. Please select another column!", :red)
          next
        end

        # Warn if there are duplicates
        unless column.size == column.uniq.size
          unless yes?("The column '#{headers[index]}' contains doublet values. Do you wish to continue?", :yellow)
            next
          end
        end

        # Warn if there are insecure (weak) election codes
        if column.any?{ |v| v.length < 14 }
          unless yes?("The column '#{headers[index]}' contains insecure values. Do you wish to continue?", :yellow)
            next
          end
        end

        election_codes = column
        break
      end

      public_keys = election_codes.map{ |ec| Crypto.election_code_to_public_key(ec) }

      # generate public keys file
      rows_plus_public_keys = rows.zip(public_keys).map{ |row, public_key| row + [public_key] }
      headers_plus_public_key = headers + ['Public key']

      pk_absolute_path = ask_output_path('.csv', 'public_keys', 'Pick a name for the public keys file')
      output(pk_absolute_path) do |csv|
        csv << headers_plus_public_key
        rows_plus_public_keys.each{ |row| csv << row }
      end

      say("Done! Outputted file:\n#{pk_absolute_path}")
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
