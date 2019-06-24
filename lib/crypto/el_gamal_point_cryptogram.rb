module Crypto
  # Instances of this class represent ElGamal cryptograms of a point,
  # which are simply a pair of points named `randomness` and 'ciphertext'
  class ElGamalPointCryptogram
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :randomness
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :ciphertext

    # @param randomness (OpenSSL::PKey::EC::Point) the value of the randomness.
    # @param ciphertext (OpenSSL::PKey::EC::Point) the value of the ciphertext.
    def initialize(randomness, ciphertext)
      @randomness, @ciphertext = randomness, ciphertext

      (randomness.is_a?(OpenSSL::PKey::EC::Point) &&
          randomness.on_curve?) or raise ArgumentError, 'randomness is not a valid point.'

      (ciphertext.is_a?(OpenSSL::PKey::EC::Point) &&
          ciphertext.on_curve?) or raise ArgumentError, 'ciphertext is not a valid point.'
    end

    # Instantiates an {ElGamalPointCryptogram} from a given string
    #
    # @param string (String) The encoded string.
    # @return (ElGamalPointCryptogram) a new point cryptogram
    def self.from_s(string)
      strings = string.split(',')

      case strings.length
      when 2
        randomness_point = Crypto.hex_to_point strings[0]
        ciphertext_point = Crypto.hex_to_point strings[1]
      else
        raise ArgumentError, 'invalid number of arguments in encoding.'
      end

      ElGamalPointCryptogram.new(randomness_point, ciphertext_point)
    end

    # Encrypts a given message that is a point
    #
    # @param message (OpenSSL::PKey::EC::Point) The message to be encrypted.
    # @param public_key (OpenSSL::PKey::EC::Point) The value of the public key.
    # @param randomness (OpenSSL::BN) The random value used to encrypt.
    # @return (ElGamalPointCryptogram) a new point cryptogram
    def self.encrypt(message, public_key, randomness)
      randomness_point = CURVE.group.generator.mul(randomness)
      # ciphertext = public_key * randomness + message * 1
      ciphertext_point = public_key.mul([randomness, OpenSSL::BN.new(1)], [message])

      ElGamalPointCryptogram.new(randomness_point, ciphertext_point)
    end

    # Decrypts a given cryptogram of a point
    #
    # @param private_key (OpenSSL::BN) The value of the decryption key.
    # @return (OpenSSL::PKey::EC::Point) The message of the cryptogram.
    def decrypt(private_key)
      shared_secret = @randomness.mul(private_key)
      shared_secret.invert!

      @ciphertext.mul([OpenSSL::BN.new(1), OpenSSL::BN.new(1)], [shared_secret])
    end

    # Outputs the cryptogram as a string with both values encoded as hex, concatenated by a comma
    #
    # @return (String) The encoded cryptogram.
    def to_s()
      Crypto.point_to_hex(@randomness) + ',' + Crypto.point_to_hex(@ciphertext)
    end
  end
end