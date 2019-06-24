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

      Dir.mkdir('outputs') unless File.exists?('outputs')

      rows_plus_election_codes = rows.zip(credential_pairs.keys).map{ |row, election_code| row + [election_code] }
      headers_plus_election_code = headers + ['Election code']
      election_codes_file = "outputs/#{basename}_election_codes.csv"
      write_csv(election_codes_file, headers_plus_election_code, rows_plus_election_codes)

      rows_plus_public_keys = rows.zip(credential_pairs.values).map{ |row, public_key| row + [public_key] }
      headers_plus_public_key = headers + ['Public key']
      public_keys_file = "outputs/#{basename}_public_keys.csv"
      write_csv(public_keys_file, headers_plus_public_key, rows_plus_public_keys)

      $stdout.puts 'Outputted files:'
      $stdout.puts election_codes_file
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
