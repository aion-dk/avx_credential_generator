module Crypto
  # Instances of this class represent Schnorr signatures,
  # which are simply a pair of integers named `payload` and 'signature'
  class SchnorrSignature
    # @return (OpenSSL::BN)
    attr_reader :payload
    # @return (OpenSSL::BN)
    attr_reader :signature

    # @param payload (OpenSSL::BN) the value of the payload.
    # @param signature (OpenSSL::BN) the value of the signature.
    def initialize(payload, signature)
      @payload, @signature = payload, signature

      (payload.is_a?(OpenSSL::BN) &&
          payload == payload % CURVE.group.order) or raise ArgumentError, 'payload is not a valid integer.'

      (signature.is_a?(OpenSSL::BN) &&
          signature == signature % CURVE.group.order) or raise ArgumentError, 'signature is not a valid integer.'
    end

    # Instantiates an {SchnorrSignature} from a given string
    #
    # @param string (String) The encoded string.
    # @return (SchnorrSignature) a new Schnorr signature
    def self.from_s(string)
      strings = string.split(',')

      case strings.length
      when 2
        payload_bn = Crypto.hex_to_bn(strings[0])
        signature_bn = Crypto.hex_to_bn(strings[1])
      else
        raise ArgumentError, 'invalid number of arguments in encoding.'
      end

      SchnorrSignature.new(payload_bn, signature_bn)
    end

    # Signs a given message and generate a Schnorr signature
    #
    # @param message (String) The message to be signed.
    # @param private_key (OpenSSL::BN) The value of the signing key.
    # @return (SchnorrSignature) a new Schnorr signature
    def self.sign(message, private_key)
      randomness_pair = CURVE.generate_key

      hash_string =
          randomness_pair.public_key.to_octet_string(:compressed) +
          message
      hash = Digest::SHA256.hexdigest(hash_string)
      payload = Crypto.hex_to_bn(hash) % CURVE.group.order

      signature = (randomness_pair.private_key - (payload * private_key)) % CURVE.group.order
      signature = signature + CURVE.group.order if signature.negative?

      SchnorrSignature.new(payload, signature)
    end

    # Verifies the {SchnorrSignature} and returns true if valid
    #
    # @param message (String) the value of the message.
    # @param public_key (OpenSSL::PKey::EC::Point) the value of the signature verification key.
    def verify(message, public_key)
      # randomness_point = generator * signature + public_key * payload
      randomness_point = CURVE.group.generator.mul([@signature, @payload], [public_key])

      hash_string =
          randomness_point.to_octet_string(:compressed) +
          message
      hash = Digest::SHA256.hexdigest(hash_string)

      @payload == Crypto.hex_to_bn(hash) % CURVE.group.order
    end

    # Outputs the signature as a string with both values encoded as hex, concatenated by a comma
    #
    # @return (String) The encoded signature.
    def to_s()
      Crypto.bn_to_hex(@payload) + ',' + Crypto.bn_to_hex(@signature)
    end
  end
end