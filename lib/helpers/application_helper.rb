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
