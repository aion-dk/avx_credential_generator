module Crypto
  # Instances of this class represent ElGamal cryptograms of an integer,
  # which are simply a pair of a point named `randomness` and an integer named 'ciphertext'
  class ElGamalScalarCryptogram
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :randomness
    # @return (OpenSSL::BN)
    attr_reader :ciphertext

    # @param randomness (OpenSSL::PKey::EC::Point) the value of the randomness.
    # @param ciphertext (OpenSSL::BN) the value of the ciphertext.
    def initialize(randomness, ciphertext)
      @randomness, @ciphertext = randomness, ciphertext

      (randomness.is_a?(OpenSSL::PKey::EC::Point) &&
          randomness.on_curve?) or raise ArgumentError, 'randomness is not a valid point.'

      (ciphertext.is_a?(OpenSSL::BN) &&
          ciphertext == ciphertext % CURVE.group.order) or raise ArgumentError, 'ciphertext is not a valid integer.'
    end

    # Instantiates an {ElGamalScalarCryptogram} from a given string
    #
    # @param string (String) The encoded string.
    # @return (ElGamalScalarCryptogram) a new point cryptogram
    def self.from_s(string)
      strings = string.split(',')

      case strings.length
      when 2
        randomness_point = Crypto.hex_to_point strings[0]
        ciphertext_bn = Crypto.hex_to_bn(strings[1])
      else
        raise ArgumentError, 'invalid number of arguments in encoding.'
      end

      ElGamalScalarCryptogram.new(randomness_point, ciphertext_bn)
    end

    # Encrypts a given message that is an integer
    #
    # @param message (OpenSSL::BN) The message to be encrypted.
    # @param public_key (OpenSSL::PKey::EC::Point) The value of the public key.
    # @param randomness (OpenSSL::BN) The random value used to encrypt.
    # @return (ElGamalScalarCryptogram) a new scalar cryptogram
    def self.encrypt(message, public_key, randomness)
      message == message % CURVE.group.order or raise ArgumentError, 'message is not a valid integer.'

      randomness_point = CURVE.group.generator.mul(randomness)

      shared_secret_point = public_key.mul(randomness)
      hash_string = shared_secret_point.to_octet_string(:compressed)
      hash = Digest::SHA256.hexdigest(hash_string)
      shared_secret_bn = Crypto.hex_to_bn(hash) % CURVE.group.order

      ciphertext = (shared_secret_bn * message) % CURVE.group.order
      ciphertext = ciphertext + CURVE.group.order if ciphertext.negative?

      ElGamalScalarCryptogram.new(randomness_point, ciphertext)
    end

    # Decrypts a given cryptogram of an integer
    #
    # @param private_key (OpenSSL::BN) The value of the decryption key.
    # @return (OpenSSL::BN) The message of the cryptogram.
    def decrypt(private_key)
      shared_secret_point = @randomness.mul(private_key)
      hash_string = shared_secret_point.to_octet_string(:compressed)
      hash = Digest::SHA256.hexdigest(hash_string)
      shared_secret_bn = Crypto.hex_to_bn(hash) % CURVE.group.order

      # message = ciphertext * shared_secret ^ -1 (mod order)
      message = (@ciphertext * shared_secret_bn.mod_inverse(CURVE.group.order)) % CURVE.group.order
      message = message + CURVE.group.order if message.negative?

      message
    end

    # Outputs the cryptogram as a string with both values encoded as hex, concatenated by a comma
    #
    # @return (String) The encoded cryptogram.
    def to_s()
      Crypto.point_to_hex(@randomness) + ',' + Crypto.bn_to_hex(@ciphertext)
    end
  end
end