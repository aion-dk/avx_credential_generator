module Crypto

# Instances of this class represent Discrete Logarithm Proofs,
# which are simply a tuple of a point named `commitment` and two integers `challenge` and 'response'.
  class DiscreteLogarithmProof
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :commitment
    # @return (OpenSSL::BN)
    attr_reader :challenge
    # @return (OpenSSL::BN)
    attr_reader :response

    # @param commitment (OpenSSL::PKey::EC::Point) the value of the commitment.
    # @param challenge (OpenSSL::BN) the value of the challenge.
    # @param response (OpenSSL::BN) the value of the response.
    def initialize(commitment, challenge, response)
      @commitment, @challenge, @response = commitment, challenge, response

      (commitment.is_a?(OpenSSL::PKey::EC::Point) &&
          commitment.on_curve?) or raise ArgumentError, 'commitment is not a valid point.'

      (challenge.is_a?(OpenSSL::BN) &&
          challenge == challenge % CURVE.group.order) or raise ArgumentError, 'challenge is not a valid integer.'

      (response.is_a?(OpenSSL::BN) &&
          response == response % CURVE.group.order) or raise ArgumentError, 'response is not a valid integer.'
    end

    # Instantiates an {DiscreteLogarithmProof} from a given string
    #
    # @param string (String) The encoded string.
    # @return (DiscreteLogarithmProof) a new discrete logarithm proof
    def self.from_s(string)
      strings = string.split(',')

      case strings.length
      when 3
        commitment_point = Crypto.hex_to_point strings[0]
        challenge_bn = Crypto.hex_to_bn(strings[1])
        response_bn = Crypto.hex_to_bn(strings[2])
      else
        raise ArgumentError, 'invalid number of arguments in encoding.'
      end

      DiscreteLogarithmProof.new(commitment_point, challenge_bn, response_bn)
    end

    # Generates a non-interactive discrete logarithm proof
    #
    # @param generator (OpenSSL::PKey::EC::Point) the value of the generator.
    # @param private_key (OpenSSL::BN) the value of the key.
    # @return (DiscreteLogarithmProof) a new discrete logarithm proof
    def self.generate(generator, private_key)
      commitment_scalar = Crypto.random_bn(CURVE.group.order)
      commitment_point = generator.mul(commitment_scalar)
      public_key = generator.mul(private_key)

      hash_string =
          generator.to_octet_string(:compressed) +
          commitment_point.to_octet_string(:compressed) +
          public_key.to_octet_string(:compressed)
      hash = Digest::SHA256.hexdigest(hash_string)
      challenge = Crypto.hex_to_bn(hash) % CURVE.group.order

      response = (commitment_scalar + (challenge * private_key)) % CURVE.group.order

      DiscreteLogarithmProof.new(commitment_point, challenge, response)
    end

    # Verifies the {DiscreteLogarithmProof} and returns true if valid
    # Verifies that the challenge is computed non-interactively
    #
    # @param generator (OpenSSL::PKey::EC::Point) the value of the generator.
    # @param public_key (OpenSSL::PKey::EC::Point) the value of the public key.
    def verify(generator, public_key)
      if verify_without_challenge(generator, public_key)
        hash_string =
            generator.to_octet_string(:compressed) +
            @commitment.to_octet_string(:compressed) +
            public_key.to_octet_string(:compressed)
        hash = Digest::SHA256.hexdigest(hash_string)

        if @challenge == Crypto.hex_to_bn(hash) % CURVE.group.order
          return true
        end
      end

      false
    end

    # Verifies the {DiscreteLogarithmProof} and returns true if valid
    # Does not verify how challenge was computed
    #
    # @param generator (OpenSSL::PKey::EC::Point) the value of the generator.
    # @param public_key (OpenSSL::PKey::EC::Point) the value of the public key.
    def verify_without_challenge(generator, public_key)
      left_hand_side = generator.mul(@response)
      # right_hand_side = commitment * 1 + public_key * challenge
      right_hand_side = @commitment.mul([OpenSSL::BN.new(1), @challenge], [public_key])

      left_hand_side == right_hand_side
    end

    # Outputs the proof as a string with all values encoded as hex, concatenated by a comma
    #
    # @return (String) The encoded proof.
    def to_s()
      Crypto.point_to_hex(@commitment) + ',' + Crypto.bn_to_hex(@challenge) + ',' + Crypto.bn_to_hex(@response)
    end
  end
end