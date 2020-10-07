require 'csv'
# require 'charlock_holmes'

module AVXCredentialGenerator
  module ApplicationHelper

    protected

    def read_csv(path, options = {})
      absolute_path = File.expand_path(path)
      content = read_file(absolute_path)
      # Remove BOM from contents
      content.sub!("\xEF\xBB\xBF", '')
      options[:col_sep] ||= detect_col_sep(content)
      CSV.parse(content, options)
    end

    def ask_header_index(headers, message)
      loop do
        say(message)
        headers.each.with_index do |name, i|
          say("#{i}) #{name}\n")
        end

        index_str = ask("Column index:")

        unless index_str.match(/^\s*\d+\s*$/)
          say("'#{index_str}' is not a valid column index", :red)
          next
        end

        index = index_str.to_i

        if index < 0 || index >= headers.size
          say("'#{index_str}' is not a valid column index", :red)
          next
        end

        return index
      end

    end

    def ask_output_path(extname = '.csv', default_name = 'out', message = 'Pick a name for the output file')
      loop do
        output_path = ask("#{message} (default: #{default_name}#{extname}):")
        output_path = default_name if output_path.strip == ''
        output_path += extname if File.extname(output_path) != extname

        absolute_output_path = File.expand_path(output_path)

        if File.exists?(absolute_output_path)
          if yes?('The file already exists. Would you like to overwrite?', :yellow)
            File.unlink(absolute_output_path)
          else
            next
          end
        end

        return absolute_output_path
      end
    end

    def output(path, &block)
      CSV.open(path, 'w+', col_sep: ';', &block)
    end


    private

    # CSV Helpers
    def read_file(path)
      content = File.read(path)
      # detection = CharlockHolmes::EncodingDetector.detect(content)
      # CharlockHolmes::Converter.convert(content, detection[:encoding], 'UTF-8')
    end

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
