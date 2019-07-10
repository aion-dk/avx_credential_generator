require 'csv'
require 'charlock_holmes'

module AVXCredentialGenerator
  module ApplicationHelper

    protected

    def read_csv(content)
      detection = CharlockHolmes::EncodingDetector.detect(content)
      content = CharlockHolmes::Converter.convert(content, detection[:encoding], 'UTF-8')


      # Remove BOM from contents
      content.sub!("\xEF\xBB\xBF", '')
      CSV.parse(content, { col_sep: detect_col_sep(content) })
    end

    def write_csv(path, headers, rows)
      File.open(path, 'w+') do |file|
        file << CSV.generate(col_sep: ';') do |csv|
          csv << headers

          rows.each{ |row| csv << row }
        end
      end
    end

    def ask_natural_number(message)
      loop do
        say(message)

        number_str = ask("Number:")

        unless number_str.match(/^\s*\d+\s*$/)
          say("'#{number_str}' must be a number greater than or equal to zero", :red)
          next
        end

        return number_str.to_i
      end
    end

    def ask_identifier_header_from_file(headers)
      message = "What is the identifier column?\n"
      message += "You can pick from the following headers:\n"
      headers.each_with_index do |header, i|
        message += "(#{i}) #{header}\n"
      end

      loop do
        index = ask_natural_number(message)

        unless 0 <= index && index < headers.size
          say("The number must be between 0 and #{headers.size - 1}", :red)
          next
        end

        return index
      end
    end

    def ask_public_keys_path(extname = '.csv', default_name = 'out')
      loop do
        file_path = ask("Pick a name for the output file (default: #{default_name}#{extname}):")
        file_path = default_name if file_path.strip == ''
        file_path += extname if File.extname(file_path) != extname

        absolute_file_path = absolute_output_path(file_path)

        if File.exists?(absolute_file_path)
          if yes?('The file already exists. Would you like to overwrite?', :yellow)
            File.unlink(absolute_file_path)
          else
            next
          end
        end

        return absolute_file_path
      end
    end

    def absolute_output_path(file_path)
      absolute_output_dir = File.expand_path('outputs')
      FileUtils.mkdir(absolute_output_dir) unless File.exists?(absolute_output_dir)

      File.expand_path(file_path, 'outputs')
    end

    private

    def detect_col_sep(contents)
      test_contents = contents.lines.first.chomp
      test_results = [',',';',"\t"].map { |col_sep| [count_col_sep(test_contents, col_sep), col_sep ] }
      test_results.sort.last.last
    end

    def count_col_sep(test_contents, col_sep)
      CSV.parse(test_contents, col_sep: col_sep).first.size
    rescue
      0
    end
  end
end
